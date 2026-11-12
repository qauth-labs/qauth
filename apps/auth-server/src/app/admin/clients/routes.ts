import { randomBytes, randomUUID } from 'node:crypto';

import { NotFoundError, PreconditionFailedError } from '@qauth-labs/shared-errors';
import {
  FIRST_PARTY_FLOWS,
  FIRST_PARTY_PROFILES,
  FIRST_PARTY_REASON_MAX_LENGTH,
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
import {
  type AdminOperation,
  type ClassifyInput,
  type OperationClassification,
  operationSchemaExtensions,
} from '../../helpers/admin-operations';
import { ENVIRONMENTS } from '../../helpers/environment-policy';
import { AGENT_MODES } from '../../helpers/scope-modes';
import { emitUserEvent } from '../../helpers/user-events';
import { requestClassification } from '../../plugins/admin-operations';
import { eligibleApproverCount } from '../approvals/eligibility';
import { approvalRequirement } from '../approvals/engine';
import { callerAccount } from '../approvals/standing';
import { changePreview, changePreviewSchema } from '../change-preview';
import {
  ADMIN_SECURITY_SCHEME,
  type AdminChange,
  type AdminTransaction,
  adminTransaction,
  recordAdminChange,
  requestAdminCaller,
} from '../pipeline';
import { clientCreateLines, CREATE_HEADER_LINES } from './approval-lines';
import {
  applyClientPatch,
  changedClientFields,
  classifyClientPatch,
  PATCHABLE_CLIENT_FIELDS,
  type PatchableClientField,
} from './fields';
import {
  assertClientSettings,
  assertShownInFull,
  CLIENT_OPERATION_IDS,
  clientCheckContext,
  readClientState,
  refuseDocumentClient,
} from './operations';
import { previewClientPatch } from './preview';
import {
  type AdminClient,
  adminClientOf,
  adminClientSchema,
  adminClientVersion,
  CLIENT_ACCESS_TOKEN_LIFESPAN_MAX,
  CLIENT_AUTH_METHODS,
  CLIENT_DESCRIPTION_MAX_LENGTH,
  CLIENT_GRANT_TYPES,
  CLIENT_LIST_MAX,
  CLIENT_REFRESH_TOKEN_LIFESPAN_MAX,
  CLIENT_RESPONSE_TYPES,
  CLIENT_URI_MAX_LENGTH,
  type OAuthClientRecord,
  PRIVATE_JWK_MEMBERS,
  storedFirstPartyPolicy,
} from './representation';

/**
 * THE CLIENT ROUTES OF THE ADMIN API (ADR-020 §3, ADR-019 Decision 7, issue
 * #632):
 *
 *   GET    /admin/v1-rc.0/realms/{realmId}/clients                       — clients.list
 *   POST   /admin/v1-rc.0/realms/{realmId}/clients                       — clients.create
 *   GET    /admin/v1-rc.0/realms/{realmId}/clients/{clientId}            — clients.get, with its ETag
 *   PATCH  /admin/v1-rc.0/realms/{realmId}/clients/{clientId}            — clients.update,
 *                                                                          a JSON Merge Patch, If-Match required
 *   POST   /admin/v1-rc.0/realms/{realmId}/clients/{clientId}/preview    — clients.preview,
 *                                                                          the same patch, nothing written
 *   DELETE /admin/v1-rc.0/realms/{realmId}/clients/{clientId}            — clients.delete, If-Match required
 *   POST   /admin/v1-rc.0/realms/{realmId}/clients/{clientId}/enable     — clients.enable, If-Match required
 *   POST   /admin/v1-rc.0/realms/{realmId}/clients/{clientId}/disable    — clients.disable, If-Match required
 *
 * `{clientId}` is the client's `id`, a UUID, as the developer API names it:
 * a CIMD client's `client_id` is a URL. A client of another realm is 404, as
 * one that does not exist. No answer carries `client_secret_hash`; a create
 * answers the plaintext secret of a client that authenticates with one,
 * once.
 *
 * Every handler that writes reads the client again under `FOR NO KEY UPDATE`
 * in its transaction and writes only while it is the version the call was
 * classified and approved against (412 otherwise). The events of a change
 * commit with it and with the call's audit row: `client.created`,
 * `client.updated`, `client.deleted`, `client.suspended`,
 * `client.suspension_lifted`, and for first-party trust and the verified
 * domain `client.first_party_changed` and `client.verified_domain_changed`.
 * Removing a first-party profile revokes every refresh token of the client in
 * the same transaction (#631).
 */

const CLIENTS_PATH = '/admin/v1-rc.0/realms/:realmId/clients';
const CLIENT_PATH = `${CLIENTS_PATH}/:clientId`;

/** The cursors of the admin client list carry this name. */
const CLIENT_LIST = 'admin.clients';

const realmParams = z.object({ realmId: z.uuid() });
const clientParams = z.object({ realmId: z.uuid(), clientId: z.uuid() });

const listQuery = pageQuerySchema.extend({
  q: z.string().min(1).max(255).optional().meta({
    description:
      'Only the clients whose client_id or name holds this text, case ignored; % and _ match themselves.',
  }),
});

/** RFC 6749 §3.3: a scope token. */
const scopeToken = z
  .string()
  .min(1)
  .max(255)
  .regex(/^[\x21\x23-\x5b\x5d-\x7e]+$/, 'a scope is printable ASCII with no space, " or \\');

const uri = z.string().min(1).max(CLIENT_URI_MAX_LENGTH);
const uriList = z.array(uri).max(CLIENT_LIST_MAX);
const scopeList = z.array(scopeToken).max(CLIENT_LIST_MAX);
const flows = z.array(z.enum(FIRST_PARTY_FLOWS)).min(1).max(FIRST_PARTY_FLOWS.length);

/**
 * A public JWK: a key with a private member is refused here, before an
 * approval of the request is filed and shows it.
 */
const publicJwk = z
  .record(z.string(), z.unknown())
  .refine((key) => !Object.keys(key).some((member) => PRIVATE_JWK_MEMBERS.has(member)), {
    message:
      'a key holds a private member (d, p, q, dp, dq, qi, oth or k): send the public key only',
  });

/**
 * Each member a create or an update takes, by its value. The keys are the
 * patchable fields of the field table (`./fields.ts`): a field the table
 * makes patchable has a schema here, or the build fails.
 */
const VALUE_SCHEMAS = {
  name: z.string().min(1).max(255),
  description: z.string().max(CLIENT_DESCRIPTION_MAX_LENGTH),
  redirectUris: uriList,
  postLogoutRedirectUris: uriList,
  backchannelLogoutUri: uri,
  backchannelLogoutSessionRequired: z.boolean(),
  scopes: scopeList,
  clientCredentialsScopes: scopeList,
  grantTypes: z.array(z.enum(CLIENT_GRANT_TYPES)).min(1).max(CLIENT_GRANT_TYPES.length),
  responseTypes: z.array(z.enum(CLIENT_RESPONSE_TYPES)).max(CLIENT_RESPONSE_TYPES.length),
  tokenEndpointAuthMethod: z.enum(CLIENT_AUTH_METHODS),
  jwks: z.strictObject({ keys: z.array(publicJwk).min(1).max(20) }),
  jwksUri: uri,
  requirePkce: z.boolean(),
  dpopBoundAccessTokens: z.boolean(),
  environment: z.enum(ENVIRONMENTS),
  isAgent: z.boolean(),
  maxAgentMode: z.enum(AGENT_MODES),
  verifiedDomain: z.string().min(1).max(253),
  firstPartyProfile: z.enum(FIRST_PARTY_PROFILES),
  firstPartyPolicy: z.strictObject({
    flows: flows.optional(),
    emailCodeAfterPassword: z.boolean().optional(),
    pkceRequired: z.boolean().optional(),
  }),
  firstPartyReason: z.string().min(1).max(FIRST_PARTY_REASON_MAX_LENGTH),
  accessTokenLifespanSeconds: z.int().min(1).max(CLIENT_ACCESS_TOKEN_LIFESPAN_MAX),
  refreshTokenLifespanSeconds: z.int().min(1).max(CLIENT_REFRESH_TOKEN_LIFESPAN_MAX),
} satisfies Record<PatchableClientField, z.ZodType>;

/** The members a create cannot leave out: they have no default. */
const REQUIRED_ON_CREATE: ReadonlySet<string> = new Set<PatchableClientField>([
  'name',
  'tokenEndpointAuthMethod',
  'grantTypes',
]);

/**
 * The body of a client update: a JSON Merge Patch (RFC 7396) of the
 * patchable members, each optional, and no other member (400 for one). `null`
 * gives a member its default; `name`, `tokenEndpointAuthMethod` and
 * `grantTypes` have none (422). `firstPartyPolicy` is merged member by
 * member, its `null` members taking their defaults.
 */
export function clientPatchBodySchema(): z.ZodType {
  const shape: Record<string, z.ZodType> = {};
  for (const name of PATCHABLE_CLIENT_FIELDS as PatchableClientField[]) {
    const value: z.ZodType =
      name === 'firstPartyPolicy'
        ? z.strictObject({
            flows: flows.nullable().optional(),
            emailCodeAfterPassword: z.boolean().nullable().optional(),
            pkceRequired: z.boolean().nullable().optional(),
          })
        : VALUE_SCHEMAS[name];
    shape[name] = value.nullable().optional();
  }
  return z.strictObject(shape).meta({ id: 'AdminClientPatch' });
}

/** The body of a client creation: the patchable members, three of them required. */
export function clientCreateBodySchema(): z.ZodType {
  const shape: Record<string, z.ZodType> = {};
  for (const name of PATCHABLE_CLIENT_FIELDS as PatchableClientField[]) {
    shape[name] = REQUIRED_ON_CREATE.has(name)
      ? VALUE_SCHEMAS[name]
      : VALUE_SCHEMAS[name].optional();
  }
  // A registration is a security operation: its approver is shown every
  // setting whole (`./approval-lines.ts`), so one that would not fit is
  // refused here, before it is filed.
  return z
    .strictObject(shape)
    .superRefine((body, context) => {
      for (const problem of clientCreateLines(body, CREATE_HEADER_LINES).problems) {
        context.addIssue({
          code: 'custom',
          message: problem.message,
          path: problem.pointer === '' ? [] : [problem.pointer.slice(1)],
        });
      }
    })
    .meta({ id: 'AdminClientCreateRequest' });
}

/** The body of an operation that takes none: absent, or an empty object. */
const emptyBody = (id: string) =>
  z.strictObject({}).optional().meta({ id, description: 'No body, or an empty object.' });

/** A new client's representation, and its secret once. */
const registeredClientSchema = adminClientSchema
  .extend({
    clientSecret: z.string().optional().meta({
      description:
        'The client secret of a client that authenticates with one, answered here once and never again. Absent for private_key_jwt and none.',
    }),
  })
  .meta({ id: 'AdminRegisteredClient' });

const clientPageSchema = pageSchema(adminClientSchema).meta({ id: 'AdminClientPage' });

/** The `ETag` of a client. */
const etagOf = (client: AdminClient): string => `"${adminClientVersion(client)}"`;

/** A client's representation as its audit diff stores it: what its version covers. */
function audited(client: AdminClient): Record<string, unknown> {
  const { lastUsedAt: _lastUsedAt, ...versioned } = client;
  return versioned;
}

/** The client of the realm the path names, locked for the handler's transaction. */
async function lockedClient(
  request: FastifyRequest,
  realmId: string,
  clientId: string
): Promise<OAuthClientRecord> {
  const row = await request.server.repositories.oauthClients.findByIdForAdminUpdate(
    realmId,
    clientId,
    adminTransaction(request)
  );
  if (row === undefined) throw new NotFoundError('OAuthClient', clientId);
  return row;
}

/**
 * The client as the call was classified, and approved, against: read again
 * under the lock in the call's transaction. A change in between is 412.
 */
async function classifiedClient(
  request: FastifyRequest,
  operationId: string,
  realmId: string,
  clientId: string
): Promise<{ readonly row: OAuthClientRecord; readonly state: AdminClient }> {
  const row = await lockedClient(request, realmId, clientId);
  const state = adminClientOf(row);
  if (adminClientVersion(state) !== requestClassification(request).stateVersion) {
    throw new PreconditionFailedError({ operation: operationId });
  }
  return { row, state };
}

/** The columns of `oauth_clients` a client's patchable members and their companions are stored in. */
function columnsOf(client: AdminClient) {
  return {
    name: client.name,
    description: client.description,
    redirectUris: client.redirectUris,
    postLogoutRedirectUris: client.postLogoutRedirectUris,
    backchannelLogoutUri: client.backchannelLogoutUri,
    backchannelLogoutUriSource: client.backchannelLogoutUriSource,
    backchannelLogoutSessionRequired: client.backchannelLogoutSessionRequired,
    scopes: client.scopes,
    clientCredentialsScopes: client.clientCredentialsScopes,
    grantTypes: client.grantTypes as OAuthClientRecord['grantTypes'],
    responseTypes: client.responseTypes as OAuthClientRecord['responseTypes'],
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    jwks: client.jwks as OAuthClientRecord['jwks'],
    jwksUri: client.jwksUri,
    requirePkce: client.requirePkce,
    dpopBoundAccessTokens: client.dpopBoundAccessTokens,
    environment: client.environment,
    isAgent: client.isAgent,
    maxAgentMode: client.maxAgentMode,
    verifiedDomain: client.verifiedDomain,
    firstPartyProfile: client.firstPartyProfile,
    firstPartyPolicy: storedFirstPartyPolicy(
      client.firstPartyPolicy
    ) as OAuthClientRecord['firstPartyPolicy'],
    firstPartyReason: client.firstPartyReason,
    accessTokenLifespanSeconds: client.accessTokenLifespanSeconds,
    refreshTokenLifespanSeconds: client.refreshTokenLifespanSeconds,
  };
}

/** The columns whose value `after` changes from `before`. */
function changedColumns(before: AdminClient, after: AdminClient) {
  const was = columnsOf(before) as Record<string, unknown>;
  return Object.fromEntries(
    Object.entries(columnsOf(after)).filter(
      ([column, value]) => JSON.stringify(value) !== JSON.stringify(was[column])
    )
  ) as Partial<ReturnType<typeof columnsOf>>;
}

/** The event options of a client event an admin caused, in the call's transaction. */
function clientEventOptions(
  request: FastifyRequest,
  realmId: string,
  client: Pick<AdminClient, 'client_id'>
) {
  return {
    tx: adminTransaction(request),
    realmId,
    subject: { type: 'client' as const, id: client.client_id },
    actor: { type: 'user' as const, id: requestAdminCaller(request).userId },
  };
}

/** The flows and PKCE member a `native_backend` client's event carries. */
function policyMembersOf(client: AdminClient) {
  return client.firstPartyProfile === 'native_backend' && client.firstPartyPolicy !== null
    ? {
        flows: [...client.firstPartyPolicy.flows],
        pkceRequired: client.firstPartyPolicy.pkceRequired,
      }
    : {};
}

/**
 * Record what a write did to the client's trust: removing a first-party
 * profile revokes every refresh token of the client (#631), and a change of
 * first-party trust or of the verified domain writes its own event, in the
 * call's transaction.
 */
async function recordTrustChanges(
  request: FastifyRequest,
  realmId: string,
  id: string,
  before: AdminClient,
  after: AdminClient
): Promise<void> {
  const tx: AdminTransaction = adminTransaction(request);
  const options = clientEventOptions(request, realmId, after);
  const firstPartyChanged =
    before.firstPartyProfile !== after.firstPartyProfile ||
    before.firstPartyReason !== after.firstPartyReason ||
    JSON.stringify(before.firstPartyPolicy) !== JSON.stringify(after.firstPartyPolicy);
  if (firstPartyChanged) {
    const revokedTokenCount =
      before.firstPartyProfile !== null && after.firstPartyProfile === null
        ? await request.server.repositories.refreshTokens.revokeAllForClient(
            id,
            'first_party_profile_removed',
            tx
          )
        : 0;
    await emitUserEvent(
      request,
      'urn:qauth:event:client.first_party_changed:v1-rc.0',
      {
        from: before.firstPartyProfile,
        to: after.firstPartyProfile,
        ...policyMembersOf(after),
        ...(after.firstPartyProfile !== null && after.firstPartyReason !== null
          ? { writtenReason: after.firstPartyReason }
          : {}),
        revokedTokenCount,
      },
      options
    );
  }
  if (before.verifiedDomain !== after.verifiedDomain) {
    await emitUserEvent(
      request,
      'urn:qauth:event:client.verified_domain_changed:v1-rc.0',
      { from: before.verifiedDomain, to: after.verifiedDomain },
      options
    );
  }
}

/**
 * The guard of the write: the change about to be stored needs no more than
 * the request was classified and authorized for. The write is conditional on
 * the version the classification read, so it never does; should it, the
 * state the request was judged against is gone: 412.
 */
function requireWithin(
  input: ClassifyInput,
  state: AdminClient,
  classification: OperationClassification
): void {
  const needed = classifyClientPatch(input, state);
  const exceeds =
    (needed.class === 'security' && classification.class !== 'security') ||
    needed.effects.some((effect) => !classification.effects.includes(effect)) ||
    needed.permissions.some((permission) => !classification.permissions.includes(permission));
  if (exceeds) throw new PreconditionFailedError({ operation: CLIENT_OPERATION_IDS.update });
}

/**
 * A client as a create starts from: no developer, provisioned by the
 * operator, switched on, every patchable member at its default. The three
 * members with none are the request's.
 */
function newClientTemplate(): AdminClient {
  return {
    id: '00000000-0000-0000-0000-000000000000',
    client_id: '',
    name: '',
    description: null,
    developerId: null,
    provisionedByOperator: true,
    dynamicallyRegistered: false,
    metadataDocument: null,
    enabled: true,
    suspended: false,
    suspendedAt: null,
    redirectUris: [],
    postLogoutRedirectUris: [],
    backchannelLogoutUri: null,
    backchannelLogoutUriSource: null,
    backchannelLogoutSessionRequired: false,
    scopes: [],
    clientCredentialsScopes: null,
    grantTypes: [],
    responseTypes: [],
    tokenEndpointAuthMethod: 'none',
    jwks: null,
    jwksUri: null,
    requirePkce: true,
    dpopBoundAccessTokens: false,
    environment: 'production',
    isAgent: false,
    maxAgentMode: null,
    verifiedDomain: null,
    firstPartyProfile: null,
    firstPartyPolicy: null,
    firstPartyReason: null,
    accessTokenLifespanSeconds: null,
    refreshTokenLifespanSeconds: null,
    createdAt: new Date(0).toISOString(),
    updatedAt: new Date(0).toISOString(),
    lastUsedAt: null,
  };
}

/** The client operations, by their key in {@link CLIENT_OPERATION_IDS}. */
type ClientOperations = Record<keyof typeof CLIENT_OPERATION_IDS, AdminOperation>;

/**
 * The client operations in the pipeline's registry, or `undefined` when it
 * holds none: a test registry built from fixture operations alone serves no
 * client route, and the server's own registry (`OPERATION_REGISTRY`) holds
 * them all.
 *
 * @throws {Error} when it holds some and not the others
 */
function clientOperations(fastify: FastifyInstance): ClientOperations | undefined {
  const entries = Object.entries(CLIENT_OPERATION_IDS).map(
    ([key, id]) => [key, fastify.adminApi.registry.get(id)] as const
  );
  const missing = entries.filter(([, operation]) => operation === undefined);
  if (missing.length === entries.length) return undefined;
  if (missing.length > 0) {
    throw new Error(
      `The admin operation registry holds only some client operations; it lacks ${missing
        .map(([key]) => CLIENT_OPERATION_IDS[key as keyof typeof CLIENT_OPERATION_IDS])
        .join(', ')}`
    );
  }
  return Object.fromEntries(entries) as ClientOperations;
}

/** Register the client routes behind the admin pipeline. */
export const clientRoutes: FastifyPluginAsync = async (fastify) => {
  const typed = fastify.withTypeProvider<ZodTypeProvider>();
  const operations = clientOperations(fastify);
  if (operations === undefined) return;
  // One body schema for the patch and its preview: they take the same patch,
  // and the document holds it once (`AdminClientPatch`).
  const patchBody = clientPatchBodySchema();
  const common = {
    'x-qauth-stability': 'experimental' as const,
    // A DPoP-bound admin token (#520).
    security: [{ [ADMIN_SECURITY_SCHEME]: [] }],
  };

  typed.get(
    CLIENTS_PATH,
    {
      config: { operation: operations.list.id },
      schema: {
        ...operationSchemaExtensions(operations.list),
        ...common,
        summary: 'List the clients of a realm',
        description:
          "Every client of the realm, whoever owns it (a developer, an operator, the client itself), newest first, one page at a time. q keeps the clients whose client_id or name holds it. The developer API's list, of a developer's own clients only, is not this one.",
        'x-qauth-errors': [400, 401, 403, 404],
        params: realmParams,
        querystring: listQuery,
        response: { 200: clientPageSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const tx = adminTransaction(request);
      const { limit, cursor, q } = request.query;
      const page = await readPage(
        {
          list: CLIENT_LIST,
          limit,
          cursor,
          position: (row: OAuthClientRecord) => ({ at: row.createdAt, id: row.id }),
          item: adminClientOf,
        },
        (keyset) =>
          request.server.repositories.oauthClients.pageByRealm(
            realmId,
            keyset,
            q === undefined ? {} : { search: q },
            tx
          )
      );
      reply.header('cache-control', 'no-store');
      return page;
    }
  );

  typed.get(
    CLIENT_PATH,
    {
      config: { operation: operations.get.id },
      schema: {
        ...operationSchemaExtensions(operations.get),
        ...common,
        summary: 'Read a client',
        description:
          'The ETag is the version of the client: an update, a deletion and lifting a suspension name it in If-Match.',
        'x-qauth-errors': [400, 401, 403, 404],
        params: clientParams,
        response: { 200: adminClientSchema },
      },
    },
    async (request, reply) => {
      const client = await readClientState(
        request.server,
        requestAdminCaller(request).targetRealm.id,
        request.params.clientId,
        adminTransaction(request)
      );
      reply.header('etag', etagOf(client)).header('cache-control', 'no-store');
      return client;
    }
  );

  typed.post(
    CLIENTS_PATH,
    {
      config: { operation: operations.create.id },
      schema: {
        ...operationSchemaExtensions(operations.create),
        ...common,
        summary: 'Register a client',
        description:
          'Registers a client no developer owns, provisioned by the operator: the server generates its id and client_id, and for client_secret_basic and client_secret_post its secret, which this answer carries once. A security operation: it needs clients.security and an approval, filed with approvals.create for this body. The checks of every registration path apply, the first-party rules (ADR-017 Decision 2) and the client token lifetimes too (422 naming each field).',
        'x-qauth-errors': [400, 401, 403, 404, 422],
        params: realmParams,
        body: clientCreateBodySchema(),
        response: { 201: registeredClientSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const realm = caller.targetRealm;
      const tx = adminTransaction(request);
      const body = request.body as Record<string, unknown>;
      const grantTypes = (body['grantTypes'] ?? []) as readonly string[];
      // A client with no authorization_code grant takes no response type.
      const withDefaults = Object.hasOwn(body, 'responseTypes')
        ? body
        : { ...body, responseTypes: grantTypes.includes('authorization_code') ? ['code'] : [] };
      const applied = applyClientPatch(newClientTemplate(), withDefaults);
      assertClientSettings(applied, await clientCheckContext(request, realm), true);
      const settings = applied.client;

      // A secret for a client that authenticates with one, answered once; a
      // client that does not gets the hash of a random value nobody holds,
      // so the column is filled and the hash's length says nothing.
      const usesSecret =
        settings.tokenEndpointAuthMethod === 'client_secret_basic' ||
        settings.tokenEndpointAuthMethod === 'client_secret_post';
      const secret = randomBytes(32).toString('hex');
      const clientSecretHash = await request.server.passwordHasher.hashPassword(secret);

      const row = await request.server.repositories.oauthClients.createByAdmin(
        {
          realmId: realm.id,
          clientId: randomUUID(),
          clientSecretHash,
          ...columnsOf(settings),
          developerId: null,
          provisionedByOperator: true,
          enabled: true,
          suspended: false,
        },
        tx
      );
      const client = adminClientOf(row);
      const options = clientEventOptions(request, realm.id, client);
      await emitUserEvent(
        request,
        'urn:qauth:event:client.created:v1-rc.0',
        {
          registration: 'admin_api',
          isPublic: client.tokenEndpointAuthMethod === 'none',
          isAgent: client.isAgent,
          grantTypes: [...client.grantTypes],
          scopes: [...client.scopes],
          authMethod: client.tokenEndpointAuthMethod,
        },
        options
      );
      await recordTrustChanges(request, realm.id, row.id, newClientTemplate(), client);
      recordAdminChange(request, {
        change: { before: null, after: audited(client) },
        annotations: {},
      } as AdminChange);
      reply
        .code(201)
        .header('etag', etagOf(client))
        .header('location', `/admin/v1-rc.0/realms/${realm.id}/clients/${row.id}`)
        .header('cache-control', 'no-store');
      return usesSecret ? { ...client, clientSecret: secret } : client;
    }
  );

  typed.patch(
    CLIENT_PATH,
    {
      config: { operation: operations.update.id },
      // After the pipeline's stages: a route of the admin listener has no
      // early hook of its own.
      preHandler: requireMergePatch,
      schema: {
        ...operationSchemaExtensions(operations.update),
        ...common,
        summary: 'Change a client',
        description:
          "A JSON Merge Patch (RFC 7396) of the client, judged on the patched client field by field, as the client field table says: changing the redirect URIs, the post-logout redirect URIs, the authentication method or keys, first-party trust, the verified domain or the agent fields, adding a grant type or a qauth: scope, setting a back-channel logout URI, widening the client_credentials scopes, switching PKCE or DPoP off, a laxer environment and a longer token lifetime need clients.security and an approval; every other change clients.write. A client's token lifetime is never longer than the realm's (422). If-Match names the ETag of the client (428 without it, 412 when it moved). A CIMD client is read-only: 409, naming its document.",
        'x-qauth-errors': [400, 401, 403, 404, 409, 412, 415, 422, 428],
        consumes: [MERGE_PATCH_MEDIA_TYPE],
        params: clientParams,
        headers: ifMatchHeadersSchema,
        body: patchBody,
        response: { 200: adminClientSchema },
      },
    },
    async (request, reply) => {
      const caller = requestAdminCaller(request);
      const realmId = caller.targetRealm.id;
      const { clientId } = request.params;
      const classification = requestClassification(request);
      const { row, state } = await classifiedClient(
        request,
        operations.update.id,
        realmId,
        clientId
      );
      refuseDocumentClient(state);
      const applied = applyClientPatch(state, request.body);
      assertClientSettings(applied, await clientCheckContext(request, caller.targetRealm));
      requireWithin(
        { method: 'PATCH', params: request.params, query: {}, body: request.body },
        state,
        classification
      );

      const changed = changedClientFields(state, applied.client);
      let after = state;
      if (changed.length > 0) {
        const updated = await request.server.repositories.oauthClients.updateByAdmin(
          realmId,
          row.id,
          changedColumns(state, applied.client),
          adminTransaction(request)
        );
        after = adminClientOf(updated);
        await recordTrustChanges(request, realmId, row.id, state, after);
        await emitUserEvent(
          request,
          'urn:qauth:event:client.updated:v1-rc.0',
          { fields: changed },
          clientEventOptions(request, realmId, after)
        );
      }
      recordAdminChange(request, {
        change: { before: audited(state), after: audited(after) },
        annotations: {},
      } as AdminChange);
      reply.header('etag', etagOf(after)).header('cache-control', 'no-store');
      return after;
    }
  );

  typed.post(
    `${CLIENT_PATH}/preview`,
    {
      config: { operation: operations.preview.id },
      // After the pipeline's stages, as the patch's.
      preHandler: requireMergePatch,
      schema: {
        ...operationSchemaExtensions(operations.preview),
        ...common,
        summary: 'Preview a change of a client',
        description:
          'Takes the JSON Merge Patch clients.update takes and answers what it would change and need, without saving it: each changed field before and after, tightening, loosening or neutral, its class, effects, permissions and scopes; for the whole patch, its class and scopes, whether it needs an approval, whether a second admin is recommended or mandatory, how many other admins could approve it, and the client’s current ETag, which the save names in If-Match. It is judged by the same field table and refused as the save is (400, 415, 422; 409 for a CIMD client, naming its document). It writes nothing and needs only clients.read.',
        'x-qauth-errors': [400, 401, 403, 404, 409, 415, 422],
        consumes: [MERGE_PATCH_MEDIA_TYPE],
        params: clientParams,
        body: patchBody,
        response: { 200: changePreviewSchema },
      },
    },
    async (request) => {
      const caller = requestAdminCaller(request);
      const realmId = caller.targetRealm.id;
      const tx = adminTransaction(request);
      const state = await readClientState(request.server, realmId, request.params.clientId, tx);
      refuseDocumentClient(state);
      const applied = applyClientPatch(state, request.body);
      assertClientSettings(applied, await clientCheckContext(request, caller.targetRealm));
      // Refused as the save is: an approver could not be shown it whole.
      assertShownInFull(
        { method: 'PATCH', params: request.params, query: {}, body: request.body },
        state,
        applied
      );
      const { registry } = request.server.adminApi;
      const preview = previewClientPatch(
        registry,
        { realmId, clientId: request.params.clientId },
        request.body,
        state
      );
      const approval =
        preview.classification.class === 'security'
          ? {
              twoAdmin: approvalRequirement().twoAdmin,
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
    CLIENT_PATH,
    {
      config: { operation: operations.delete.id },
      schema: {
        ...operationSchemaExtensions(operations.delete),
        ...common,
        summary: 'Delete a client',
        description:
          'Deletes the client with its authorization codes, refresh tokens, consents and API keys. A security operation: it needs clients.security and an approval, filed against the client as it stands; If-Match names its ETag (428 without it, 412 when it moved). A CIMD client is read-only: 409, naming its document.',
        'x-qauth-errors': [400, 401, 403, 404, 409, 412, 428],
        params: clientParams,
        headers: ifMatchHeadersSchema,
        // No body; an approval binds the request as it is sent, so one that
        // sends `{}` is approved only as filed with `{}`.
        body: emptyBody('AdminClientDeleteRequest'),
        response: { 204: z.null().meta({ description: 'The client is deleted.' }) },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const { row, state } = await classifiedClient(
        request,
        operations.delete.id,
        realmId,
        request.params.clientId
      );
      refuseDocumentClient(state);
      await request.server.repositories.oauthClients.delete(
        realmId,
        row.id,
        adminTransaction(request)
      );
      await emitUserEvent(
        request,
        'urn:qauth:event:client.deleted:v1-rc.0',
        {},
        clientEventOptions(request, realmId, state)
      );
      recordAdminChange(request, {
        change: { before: audited(state), after: null },
        annotations: {},
      } as AdminChange);
      reply.code(204);
      return undefined;
    }
  );

  typed.post(
    `${CLIENT_PATH}/enable`,
    {
      config: { operation: operations.enable.id },
      schema: {
        ...operationSchemaExtensions(operations.enable),
        ...common,
        summary: 'Enable a client',
        description:
          "Lifts the client's suspension, and switches on a client no developer owns; a developer's own switch stays theirs. A security operation: the client obtains tokens again, so it needs clients.security and an approval, filed against the client as it stands; If-Match names its ETag (428 without it, 412 when it moved). It takes no body, or an empty object. A client already enabled is answered as it is.",
        'x-qauth-errors': [400, 401, 403, 404, 412, 428],
        params: clientParams,
        headers: ifMatchHeadersSchema,
        body: emptyBody('AdminClientEnableRequest'),
        response: { 200: adminClientSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const { row, state } = await classifiedClient(
        request,
        operations.enable.id,
        realmId,
        request.params.clientId
      );
      const switchOn = state.developerId === null && !state.enabled;
      let after = state;
      if (state.suspended || switchOn) {
        const updated = await request.server.repositories.oauthClients.updateByAdmin(
          realmId,
          row.id,
          { suspended: false, suspendedAt: null, ...(switchOn ? { enabled: true } : {}) },
          adminTransaction(request)
        );
        after = adminClientOf(updated);
        if (state.suspended) {
          await emitUserEvent(
            request,
            'urn:qauth:event:client.suspension_lifted:v1-rc.0',
            {},
            clientEventOptions(request, realmId, after)
          );
        }
      }
      recordAdminChange(request, {
        change: { before: audited(state), after: audited(after) },
        annotations: {},
      } as AdminChange);
      reply.header('etag', etagOf(after)).header('cache-control', 'no-store');
      return after;
    }
  );

  typed.post(
    `${CLIENT_PATH}/disable`,
    {
      config: { operation: operations.disable.id },
      schema: {
        ...operationSchemaExtensions(operations.disable),
        ...common,
        summary: 'Suspend a client',
        description:
          'Suspends the client: it obtains no token until clients.enable lifts the suspension, and its owner cannot lift it. A write, which only takes tokens away, needing clients.write and no approval; for a client that holds an admin scope (qauth:admin:*), a security operation, needing clients.security and an approval, since no new admin token is issued through it once it is suspended. If-Match names its ETag (428 without it, 412 when it moved). It takes no body, or an empty object. A client already suspended is answered as it is.',
        'x-qauth-errors': [400, 401, 403, 404, 412, 428],
        params: clientParams,
        headers: ifMatchHeadersSchema,
        body: emptyBody('AdminClientDisableRequest'),
        response: { 200: adminClientSchema },
      },
    },
    async (request, reply) => {
      const realmId = requestAdminCaller(request).targetRealm.id;
      const { row, state } = await classifiedClient(
        request,
        operations.disable.id,
        realmId,
        request.params.clientId
      );
      let after = state;
      if (!state.suspended) {
        const updated = await request.server.repositories.oauthClients.updateByAdmin(
          realmId,
          row.id,
          { suspended: true, suspendedAt: Date.now() },
          adminTransaction(request)
        );
        after = adminClientOf(updated);
        await emitUserEvent(
          request,
          'urn:qauth:event:client.suspended:v1-rc.0',
          {},
          clientEventOptions(request, realmId, after)
        );
      }
      recordAdminChange(request, {
        change: { before: audited(state), after: audited(after) },
        annotations: {},
      } as AdminChange);
      reply.header('etag', etagOf(after)).header('cache-control', 'no-store');
      return after;
    }
  );
};
