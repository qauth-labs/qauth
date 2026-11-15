import { isDeepStrictEqual } from 'node:util';

import {
  NotFoundError,
  PreconditionFailedError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import {
  ANY_CLIENT,
  PROTECTED_RESOURCE_LIMITS,
  protectedResourceClientsSchema,
  protectedResourceIndicatorSchema,
  protectedResourceScopesSchema,
} from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyPluginAsync, FastifyRequest } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import {
  ifMatchHeadersSchema,
  MERGE_PATCH_MEDIA_TYPE,
  requireMergePatch,
} from '../../api-conventions/conditional-requests';
import { readPage } from '../../api-conventions/cursor';
import { pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { type AdminOperation, operationSchemaExtensions } from '../../helpers/admin-operations';
import { requestClassification } from '../../plugins/admin-operations';
import { eligibleApproverCount } from '../approvals/eligibility';
import { callerAccount } from '../approvals/standing';
import { requestApprovalRequirement } from '../approvals/two-admin';
import { changePreview, changePreviewSchema } from '../change-preview';
import {
  ADMIN_SECURITY_SCHEME,
  type AdminChange,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { CREATE_HEADER_LINES, resourceServerCreateLines } from './approval-lines';
import {
  assertResourceServerUpdate,
  normalisedScopes,
  readResourceServerState,
  RESOURCE_SERVER_ENTITY,
  RESOURCE_SERVER_OPERATION_IDS,
  type ResourceServerSettings,
} from './operations';
import { previewResourceServerPatch } from './preview';
import {
  type AdminResourceServer,
  adminResourceServerOf,
  adminResourceServerSchema,
  adminResourceServerVersion,
  type ProtectedResourceRecord,
} from './representation';

/**
 * THE RESOURCE SERVER ROUTES OF THE ADMIN API (ADR-019 Decision 7, issue
 * #1087):
 *
 *   GET    /admin/v1-rc.0/realms/{realmId}/resource-servers                              — resourceServers.list
 *   POST   /admin/v1-rc.0/realms/{realmId}/resource-servers                              — resourceServers.create
 *   GET    /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}           — resourceServers.get, with its ETag
 *   PATCH  /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}           — resourceServers.update,
 *                                                                                          a JSON Merge Patch, If-Match required
 *   POST   /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}/preview   — resourceServers.preview,
 *                                                                                          the same patch, nothing written
 *   DELETE /admin/v1-rc.0/realms/{realmId}/resource-servers/{resourceServerId}           — resourceServers.delete, If-Match required
 *
 * `{resourceServerId}` is the row's `id`, a UUID: a resource indicator is a
 * URI. A resource server of another realm is 404, as one that does not
 * exist. A registration of an indicator the realm already registered is 409
 * (`already_exists`).
 *
 * Every handler that writes reads the resource server again under
 * `FOR NO KEY UPDATE` in its transaction and writes only while it is the
 * version the call was classified and approved against (412 otherwise). The
 * call's audit row and its `admin.change_applied` event record the change,
 * before and after, and commit with it.
 */

const RESOURCE_SERVERS_PATH = '/admin/v1-rc.0/realms/:realmId/resource-servers';
const RESOURCE_SERVER_PATH = `${RESOURCE_SERVERS_PATH}/:resourceServerId`;

/** The cursors of the admin resource server list carry this name. */
const RESOURCE_SERVER_LIST = 'admin.resourceServers';

/** The unique constraint a second registration of one indicator in a realm meets. */
const REALM_RESOURCE_CONSTRAINT = 'protected_resources_realm_resource';

const realmParams = z.object({ realmId: z.uuid() });
const resourceServerParams = z.object({ realmId: z.uuid(), resourceServerId: z.uuid() });

/** A JSON Pointer of the lines' problems as a Zod issue path. */
const pathOf = (pointer: string): (string | number)[] =>
  pointer === ''
    ? []
    : pointer
        .slice(1)
        .split('/')
        .map((part) => (/^\d+$/.test(part) ? Number(part) : part));

/**
 * The body of a registration: the resource indicator, the scopes it defines
 * and who may ask for them, by the rules the seed manifest keeps too
 * (`@qauth-labs/shared-validation`). A registration is a security operation:
 * its approver is shown every value whole (`./approval-lines.ts`), so one
 * that would not fit is refused here, before it is filed. One instance, so
 * the document holds it once.
 */
export const resourceServerCreateBodySchema = z
  .strictObject({
    resource: protectedResourceIndicatorSchema,
    scopes: protectedResourceScopesSchema,
    clients: protectedResourceClientsSchema,
  })
  .superRefine((body, context) => {
    for (const problem of resourceServerCreateLines(body, CREATE_HEADER_LINES).problems) {
      context.addIssue({ code: 'custom', message: problem.message, path: pathOf(problem.pointer) });
    }
  })
  .meta({ id: 'AdminResourceServerCreateRequest' });

/**
 * The body of an update and of its preview: a JSON Merge Patch (RFC 7396).
 * `scopes` and `clients` replace the stored value whole, and have no default
 * to be removed to (`null`, 422). `resource` may be named only as it is
 * stored: the indicator never changes (422). No other member (400). One
 * instance for the patch and its preview: the document holds it once.
 */
export const resourceServerPatchBodySchema = z
  .strictObject({
    resource: z.string().max(PROTECTED_RESOURCE_LIMITS.resourceMaxLength).nullable().optional(),
    scopes: protectedResourceScopesSchema.nullable().optional(),
    clients: protectedResourceClientsSchema.nullable().optional(),
  })
  .meta({ id: 'AdminResourceServerPatch' });

/**
 * No body, or an empty object. A call that sends no body reaches the handler
 * with `null` (Fastify), as the approval it carries files it (`null` too).
 */
const deleteBody = z
  .strictObject({})
  .nullable()
  .optional()
  .meta({ id: 'AdminResourceServerDeleteRequest', description: 'No body, or an empty object.' });

const resourceServerPageSchema = pageSchema(adminResourceServerSchema).meta({
  id: 'AdminResourceServerPage',
});

/** The `ETag` of a resource server. */
const etagOf = (server: AdminResourceServer): string => `"${adminResourceServerVersion(server)}"`;

/** The columns of `protected_resources` that `settings` are stored in. */
function columnsOf(settings: ResourceServerSettings) {
  return {
    scopes: settings.scopes,
    anyClient: settings.clients === ANY_CLIENT,
    clientIds: settings.clients === ANY_CLIENT ? [] : settings.clients,
  };
}

/**
 * The resource server as the call was classified, and approved, against:
 * read again under the lock in the call's transaction. A change in between is
 * 412.
 */
async function classifiedResourceServer(
  request: FastifyRequest,
  operationId: string,
  realmId: string,
  resourceServerId: string
): Promise<{ readonly row: ProtectedResourceRecord; readonly state: AdminResourceServer }> {
  const row = await request.server.repositories.protectedResources.findByIdForUpdate(
    realmId,
    resourceServerId,
    adminTransaction(request)
  );
  if (row === undefined) throw new NotFoundError(RESOURCE_SERVER_ENTITY, resourceServerId);
  const state = adminResourceServerOf(row);
  if (adminResourceServerVersion(state) !== requestClassification(request).stateVersion) {
    throw new PreconditionFailedError({ operation: operationId });
  }
  return { row, state };
}

/** The resource server operations, by their key in {@link RESOURCE_SERVER_OPERATION_IDS}. */
type ResourceServerOperations = Record<keyof typeof RESOURCE_SERVER_OPERATION_IDS, AdminOperation>;

/**
 * The resource server operations in the pipeline's registry, or `undefined`
 * when it holds none: a test registry built from fixture operations alone
 * serves no resource server route, and the server's own registry
 * (`OPERATION_REGISTRY`) holds them all.
 *
 * @throws {Error} when it holds some and not the others
 */
function resourceServerOperations(fastify: FastifyInstance): ResourceServerOperations | undefined {
  const entries = Object.entries(RESOURCE_SERVER_OPERATION_IDS).map(
    ([key, id]) => [key, fastify.adminApi.registry.get(id)] as const
  );
  const missing = entries.filter(([, operation]) => operation === undefined);
  if (missing.length === entries.length) return undefined;
  if (missing.length > 0) {
    throw new Error(
      `The admin operation registry holds only some resource server operations; it lacks ${missing
        .map(
          ([key]) =>
            RESOURCE_SERVER_OPERATION_IDS[key as keyof typeof RESOURCE_SERVER_OPERATION_IDS]
        )
        .join(', ')}`
    );
  }
  return Object.fromEntries(entries) as ResourceServerOperations;
}

/** Register the resource server routes behind the admin pipeline. */
export const resourceServerRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = resourceServerOperations(fastify);
  if (operations === undefined) return;
  const common = {
    'x-qauth-stability': 'experimental' as const,
    // A DPoP-bound admin token (#520).
    security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
  };

  typed.get(
    RESOURCE_SERVERS_PATH,
    {
      config: { operation: operations.list.id },
      schema: {
        ...operationSchemaExtensions(operations.list),
        ...common,
        summary: 'List the resource servers of a realm',
        description:
          'Every resource server (protected resource, RFC 8707 and RFC 9728) the realm registers, newest first, one page at a time, each with the scopes it defines, their consent texts by locale and who may ask for them.',
        'x-qauth-errors': [400, 401, 403, 404],
        params: realmParams,
        querystring: pageQuerySchema,
        response: { 200: resourceServerPageSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const tx = adminTransaction(request);
      const { limit, cursor } = request.query;
      const page = await readPage(
        {
          list: RESOURCE_SERVER_LIST,
          limit,
          cursor,
          position: (row: ProtectedResourceRecord) => ({ at: row.createdAt, id: row.id }),
          item: adminResourceServerOf,
        },
        (keyset) => request.server.repositories.protectedResources.pageByRealm(realmId, keyset, tx)
      );
      reply.header('cache-control', 'no-store');
      return page;
    }
  );

  typed.get(
    RESOURCE_SERVER_PATH,
    {
      config: { operation: operations.get.id },
      schema: {
        ...operationSchemaExtensions(operations.get),
        ...common,
        summary: 'Read a resource server',
        description:
          'The ETag is the version of the resource server: an update and a deletion name it in If-Match.',
        'x-qauth-errors': [400, 401, 403, 404],
        params: resourceServerParams,
        response: { 200: adminResourceServerSchema },
      },
    },
    async (request, reply) => {
      const server = await readResourceServerState(
        request.server,
        requestAdminCaller(request).targetRealm.id,
        request.params.resourceServerId,
        adminTransaction(request)
      );
      reply.header('etag', etagOf(server)).header('cache-control', 'no-store');
      return server;
    }
  );

  typed.post(
    RESOURCE_SERVERS_PATH,
    {
      config: { operation: operations.create.id },
      schema: {
        ...operationSchemaExtensions(operations.create),
        ...common,
        summary: 'Register a resource server',
        description:
          'Registers a resource server: its resource indicator (an absolute URI with no fragment, never a QAuth API audience), the scopes it defines, each with its consent text by BCP 47 locale (en always among them) and whether it is sensitive, and who may ask for them, any_client or a list of client_ids. Each scope is then granted only when an authorization request names this resource, to a client it is open to, whatever the client’s own scopes list. A security operation: it needs resourceServers.security and an approval, filed with approvals.create for this body; a registration an approver could not be shown in full is refused (400). An indicator the realm already registered is 409.',
        'x-qauth-errors': [400, 401, 403, 404, 409],
        params: realmParams,
        body: resourceServerCreateBodySchema,
        response: { 201: adminResourceServerSchema },
      },
    },
    async (request, reply) => {
      const realm = requestAdminCaller(request).targetRealm;
      const { resource, scopes, clients } = request.body;
      const row = await request.server.repositories.protectedResources.create(
        realm.id,
        resource,
        columnsOf({ scopes: normalisedScopes(scopes), clients }),
        adminTransaction(request)
      );
      if (row === undefined) throw new UniqueConstraintError(REALM_RESOURCE_CONSTRAINT);
      const server = adminResourceServerOf(row);
      recordAdminChange(request, {
        change: { before: null, after: server },
        annotations: {},
      } as AdminChange);
      reply
        .code(201)
        .header('etag', etagOf(server))
        .header('location', `/admin/v1-rc.0/realms/${realm.id}/resource-servers/${row.id}`)
        .header('cache-control', 'no-store');
      return server;
    }
  );

  typed.patch(
    RESOURCE_SERVER_PATH,
    {
      config: { operation: operations.update.id },
      // After the pipeline's stages: a route of the admin listener has no
      // early hook of its own.
      preHandler: requireMergePatch,
      schema: {
        ...operationSchemaExtensions(operations.update),
        ...common,
        summary: 'Change a resource server',
        description:
          'A JSON Merge Patch (RFC 7396) of the resource server: scopes and clients, when named, replace the stored value whole; null removes neither (422). The resource indicator never changes (422): register another resource server for another one. Every change is a security operation, a narrowing too: it needs resourceServers.security and an approval, and a change an approver could not be shown in full is refused (422). If-Match names the ETag of the resource server (428 without it, 412 when it moved).',
        'x-qauth-errors': [400, 401, 403, 404, 412, 415, 422, 428],
        consumes: [MERGE_PATCH_MEDIA_TYPE],
        params: resourceServerParams,
        headers: ifMatchHeadersSchema,
        body: resourceServerPatchBodySchema,
        response: { 200: adminResourceServerSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const tx = adminTransaction(request);
      const { row, state } = await classifiedResourceServer(
        request,
        operations.update.id,
        realmId,
        request.params.resourceServerId
      );
      const settings = assertResourceServerUpdate(state, request.body);
      let after = state;
      if (!isDeepStrictEqual({ scopes: state.scopes, clients: state.clients }, settings)) {
        const updated = await request.server.repositories.protectedResources.update(
          realmId,
          row.id,
          columnsOf(settings),
          row.version,
          tx
        );
        if (updated === undefined) {
          throw new PreconditionFailedError({ operation: operations.update.id });
        }
        after = adminResourceServerOf(updated);
      }
      recordAdminChange(request, {
        change: { before: state, after },
        annotations: {},
      } as AdminChange);
      reply.header('etag', etagOf(after)).header('cache-control', 'no-store');
      return after;
    }
  );

  typed.post(
    `${RESOURCE_SERVER_PATH}/preview`,
    {
      config: { operation: operations.preview.id },
      // After the pipeline's stages, as the patch's.
      preHandler: requireMergePatch,
      schema: {
        ...operationSchemaExtensions(operations.preview),
        ...common,
        summary: 'Preview a change of a resource server',
        description:
          'Takes the JSON Merge Patch resourceServers.update takes and answers what it would change and need, without saving it: the scopes and who may ask for them, each before and after, tightening, loosening or neutral; for the whole patch, its class and scopes, that it needs an approval, whether a second admin is recommended or mandatory, how many other admins could approve it, and the resource server’s current ETag, which the save names in If-Match. It is refused as the save is (400, 415, 422). It writes nothing and needs only resourceServers.read.',
        'x-qauth-errors': [400, 401, 403, 404, 415, 422],
        consumes: [MERGE_PATCH_MEDIA_TYPE],
        params: resourceServerParams,
        body: resourceServerPatchBodySchema,
        response: { 200: changePreviewSchema },
      },
    },
    async (request) => {
      const caller = requestAdminCaller(request);
      const realmId = caller.targetRealm.id;
      const tx = adminTransaction(request);
      const state = await readResourceServerState(
        request.server,
        realmId,
        request.params.resourceServerId,
        tx
      );
      // Refused as the save is: the indicator, a required member, and a
      // change an approver could not be shown whole.
      assertResourceServerUpdate(state, request.body);
      const { registry } = request.server.adminApi;
      const preview = previewResourceServerPatch(
        registry,
        { realmId, resourceServerId: request.params.resourceServerId },
        request.body,
        state
      );
      const approval =
        preview.classification.class === 'security'
          ? {
              twoAdmin: requestApprovalRequirement(request.server, {
                operation: operations.update,
                realm: caller.targetRealm,
                body: request.body,
              }).twoAdmin,
              eligibleApprovers: await eligibleApproverCount(request.server, {
                targetRealm: caller.targetRealm,
                requester: callerAccount(caller),
                callerRealm: caller.issuerRealm,
                tx,
              }),
            }
          : null;
      return changePreview(
        {
          etag: etagOf(state),
          classification: preview.classification,
          changes: preview.changes,
          approval,
        },
        registry.permissions
      );
    }
  );

  typed.delete(
    RESOURCE_SERVER_PATH,
    {
      config: { operation: operations.delete.id },
      schema: {
        ...operationSchemaExtensions(operations.delete),
        ...common,
        summary: 'Delete a resource server',
        description:
          'Deletes the resource server: its scopes are no longer bound to its resource, so one no other resource server defines is granted again only to a client whose own scopes list it. Tokens already issued keep what they carry until they expire. A security operation: it needs resourceServers.security and an approval, filed against the resource server as it stands; If-Match names its ETag (428 without it, 412 when it moved).',
        'x-qauth-errors': [400, 401, 403, 404, 412, 428],
        params: resourceServerParams,
        headers: ifMatchHeadersSchema,
        // No body; an approval binds the request as it is sent, so one that
        // sends `{}` is approved only as filed with `{}`.
        body: deleteBody,
        response: { 204: z.null().meta({ description: 'The resource server is deleted.' }) },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const { row, state } = await classifiedResourceServer(
        request,
        operations.delete.id,
        realmId,
        request.params.resourceServerId
      );
      const removed = await request.server.repositories.protectedResources.delete(
        realmId,
        row.id,
        row.version,
        adminTransaction(request)
      );
      if (!removed) throw new PreconditionFailedError({ operation: operations.delete.id });
      recordAdminChange(request, {
        change: { before: state, after: null },
        annotations: {},
      } as AdminChange);
      reply.code(204);
      return undefined;
    }
  );
};
