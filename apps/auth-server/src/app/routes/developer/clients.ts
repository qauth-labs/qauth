import { PreconditionFailedError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  entityTagOf,
  entityTagValue,
  ifMatchAllows,
  ifMatchHeadersSchema,
  MERGE_PATCH_MEDIA_TYPE,
  requireIfMatch,
  requireMergePatch,
} from '../../api-conventions/conditional-requests';
import { readPage } from '../../api-conventions/cursor';
import { API_FAMILY_PREFIXES } from '../../api-conventions/families';
import { pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { rfc3339, rfc3339OrNull } from '../../api-conventions/time';
import { UnprocessableContentError } from '../../helpers/api-request-errors';
import {
  applyClientChange,
  type ClientSettingsChange,
  createDeveloperClient,
  deleteDeveloperClient,
  NEW_CLIENT_DEFAULTS,
  type OAuthClientRow,
  recordClientUpdated,
  regenerateDeveloperClientSecret,
  requireDeveloperId,
  resolveClientPolicy,
  resolveOwnedClient,
  withClientPolicies,
} from '../../helpers/developer-clients';
import type { EnvironmentPolicy } from '../../helpers/environment-policy';
import { requireFamilyToken } from '../../helpers/family-token';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
import {
  createdDeveloperClientSchema,
  createDeveloperClientRequestSchema,
  type DeveloperClient,
  type DeveloperClientPatch,
  developerClientPatchSchema,
  developerClientSchema,
  regeneratedDeveloperClientSchema,
} from '../../schemas/developer-api';

/**
 * The developer API's clients (#524): `/developer/v1-rc.0/clients`.
 *
 *   GET    /clients                               — list, a page at a time
 *   POST   /clients                               — create
 *   GET    /clients/{clientId}                    — read one, with its ETag
 *   PATCH  /clients/{clientId}                    — merge patch, If-Match required
 *   DELETE /clients/{clientId}                    — delete
 *   POST   /clients/{clientId}/regenerate-secret  — issue a new secret
 *
 * `{clientId}` is the client's `id`, the UUID of its row, not its OAuth
 * `client_id`.
 */

const clientParamsSchema = z.object({ clientId: z.uuid() });

/** The tag every operation of the developer API carries. */
const TAGS = ['Developer API'];

/**
 * The client's representation. The secret hash and the internal columns are
 * never serialized; `environment` and `staticApiKeysAllowed` are the
 * EFFECTIVE policy (ADR-008 §7) against the realm's ceiling.
 */
export function toDeveloperClient(
  client: OAuthClientRow,
  policy: EnvironmentPolicy
): DeveloperClient {
  return {
    id: client.id,
    client_id: client.clientId,
    client_name: client.name,
    description: client.description,
    redirect_uris: client.redirectUris,
    scopes: client.scopes,
    grant_types: client.grantTypes,
    response_types: client.responseTypes,
    token_endpoint_auth_method: client.tokenEndpointAuthMethod,
    enabled: client.enabled,
    suspended: client.suspended,
    requirePkce: client.requirePkce,
    environment: policy.environment,
    staticApiKeysAllowed: policy.staticApiKeysAllowed,
    createdAt: rfc3339(client.createdAt),
    updatedAt: rfc3339(client.updatedAt),
    lastUsedAt: rfc3339OrNull(client.lastUsedAt),
  };
}

/**
 * The client's `ETag`: the strong tag of its representation, `lastUsedAt`
 * left out. `lastUsedAt` is usage data no update writes: were it in the tag,
 * every token the client obtains would make its owner's pending edit stale.
 * Every member an update reads or writes is in it, `updatedAt` included.
 */
export function developerClientEntityTag(client: DeveloperClient): string {
  return entityTagOf({ ...client, lastUsedAt: undefined });
}

/**
 * What a merge patch changes (RFC 7396). A member left out keeps its value; a
 * member set to `null` takes the value a create gives it when it is left out.
 * `client_name` has none, so `null` there is refused with 422.
 */
function changeOfPatch(patch: DeveloperClientPatch): ClientSettingsChange {
  if (patch.client_name === null) {
    throw new UnprocessableContentError([
      { pointer: '/client_name', message: 'client_name is required and has no default' },
    ]);
  }
  const change: ClientSettingsChange = {};
  if (patch.client_name !== undefined) change.name = patch.client_name;
  if (patch.description !== undefined) change.description = patch.description;
  if (patch.redirect_uris !== undefined) change.redirectUris = patch.redirect_uris ?? [];
  if (patch.scopes !== undefined) change.scopes = patch.scopes ?? [];
  if (patch.grant_types !== undefined) {
    change.grantTypes = patch.grant_types ?? [...NEW_CLIENT_DEFAULTS.grantTypes];
  }
  if (patch.response_types !== undefined) {
    change.responseTypes = patch.response_types ?? [...NEW_CLIENT_DEFAULTS.responseTypes];
  }
  if (patch.token_endpoint_auth_method !== undefined) {
    change.tokenEndpointAuthMethod =
      patch.token_endpoint_auth_method ?? NEW_CLIENT_DEFAULTS.tokenEndpointAuthMethod;
  }
  if (patch.enabled !== undefined) change.enabled = patch.enabled ?? true;
  return change;
}

/** The rate limit of the routes that run an argon2id hash: create and regenerate. */
function hashingRateLimit() {
  return {
    max: env.REGISTER_CLIENT_RATE_LIMIT,
    timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
    keyGenerator: realmRateLimitKey,
  };
}

export function registerDeveloperClientRoutes(fastify: FastifyInstance): void {
  const guard = requireFamilyToken('developer', { subjects: ['user'] });
  const typed = fastify.withTypeProvider<ZodTypeProvider>();

  typed.get(
    '/clients',
    {
      // Before validation: a caller without a developer token learns nothing
      // about what the route accepts.
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.list',
        description:
          "List the OAuth clients the token's developer owns, newest first, one page at a time. A client registered anonymously (dynamic registration, a Client ID Metadata Document) has no owner and is never listed (ADR-012).",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'read',
        'x-qauth-permission': 'clients.read',
        'x-qauth-errors': [400, 401],
        querystring: pageQuerySchema,
        response: { 200: pageSchema(developerClientSchema) },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const realmId = requestRealm(request).id;
      // `developer_id = $1`, never `OR developer_id IS NULL`: the equality is
      // the only tenant boundary on the table (ADR-012).
      const page = await readPage(
        {
          list: 'developer.clients',
          limit: request.query.limit,
          cursor: request.query.cursor,
          position: (row: OAuthClientRow) => ({ at: row.createdAt, id: row.id }),
          item: (row: OAuthClientRow) => row,
        },
        (keyset) => fastify.repositories.oauthClients.pageByDeveloper(realmId, developerId, keyset)
      );
      const items = (await withClientPolicies(fastify, page.items)).map(({ client, policy }) =>
        toDeveloperClient(client, policy)
      );
      reply.header('Cache-Control', 'no-store');
      return reply.send({ items, nextCursor: page.nextCursor });
    }
  );

  typed.post(
    '/clients',
    {
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.create',
        description:
          "Create an OAuth client owned by the token's developer. The server generates `client_id` and, for a confidential client, `client_secret`, which this answer carries once and never again. The checks of dynamic registration apply: the realm's scope allowlist, the redirect URI rules and the per-developer client limit.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'write',
        'x-qauth-permission': 'clients.write',
        'x-qauth-errors': [400, 401, 403],
        body: createDeveloperClientRequestSchema,
        response: { 201: createdDeveloperClientSchema },
      },
      // Create runs an argon2id hash on every call: capped per address.
      config: { surface: 'api', rateLimit: hashingRateLimit() },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const body = request.body;
      const { client, policy, clientSecret } = await createDeveloperClient(
        fastify,
        request,
        developerId,
        {
          name: body.client_name,
          description: body.description ?? null,
          redirectUris: body.redirect_uris,
          scopes: body.scopes,
          ...(body.grant_types === undefined ? {} : { grantTypes: body.grant_types }),
          ...(body.response_types === undefined ? {} : { responseTypes: body.response_types }),
          ...(body.token_endpoint_auth_method === undefined
            ? {}
            : { tokenEndpointAuthMethod: body.token_endpoint_auth_method }),
        }
      );
      const representation = toDeveloperClient(client, policy);
      // The answer carries the plaintext secret once — MUST NOT be cached.
      reply
        .header('Cache-Control', 'no-store')
        .header('Pragma', 'no-cache')
        .header('ETag', developerClientEntityTag(representation))
        .header('Location', `${API_FAMILY_PREFIXES.developer}/clients/${client.id}`);
      return reply.code(201).send({
        ...representation,
        ...(clientSecret === undefined ? {} : { client_secret: clientSecret }),
      });
    }
  );

  typed.get(
    '/clients/:clientId',
    {
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.get',
        description:
          "Read one of the token's developer's OAuth clients, with its `ETag`. A client that does not exist or that another developer owns is 404 (ADR-012). Never returns the client secret.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'read',
        'x-qauth-permission': 'clients.read',
        'x-qauth-errors': [400, 401, 404],
        params: clientParamsSchema,
        response: { 200: developerClientSchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const client = await resolveOwnedClient(
        fastify,
        request,
        developerId,
        request.params.clientId
      );
      const representation = toDeveloperClient(client, await resolveClientPolicy(fastify, client));
      reply
        .header('Cache-Control', 'no-store')
        .header('ETag', developerClientEntityTag(representation));
      return reply.send(representation);
    }
  );

  typed.patch(
    '/clients/:clientId',
    {
      // The token first, then the media type and `If-Match`, all before the
      // body is validated: 401, then 415, then 428, then 400. Fastify parses
      // the body before these hooks, though: a media type no parser of the
      // module takes is 415, and a body the parser cannot read is 400, before
      // the token is checked.
      preValidation: [guard, requireMergePatch, requireIfMatch],
      schema: {
        operationId: 'developer.clients.update',
        description:
          "Change one of the token's developer's OAuth clients with a JSON Merge Patch (RFC 7396). `If-Match` must name the client's current `ETag`: 428 without it, 412 when the client changed since. A member set to `null` takes the value a create gives it when it is left out; `client_name` has none, so `null` there is 422. `enabled` is the owner's switch and does not lift an operator's suspension. A client of another developer is 404.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'write',
        'x-qauth-permission': 'clients.write',
        'x-qauth-errors': [400, 401, 404, 412, 415, 422, 428],
        consumes: [MERGE_PATCH_MEDIA_TYPE],
        params: clientParamsSchema,
        headers: ifMatchHeadersSchema,
        body: developerClientPatchSchema,
        response: { 200: developerClientSchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { clientId } = request.params;
      const patch = request.body;

      // Read, compare and write under the row's lock, so no other update
      // lands between the version `If-Match` names and this write. Every read
      // in it goes through `tx`, so it never waits for a second connection.
      const { client, fields } = await fastify.db.transaction(async (tx) => {
        const existing = await resolveOwnedClient(fastify, request, developerId, clientId, tx);
        const current = toDeveloperClient(
          existing,
          await resolveClientPolicy(fastify, existing, tx)
        );
        if (
          !ifMatchAllows(
            request.headers['if-match'],
            entityTagValue(developerClientEntityTag(current))
          )
        ) {
          throw new PreconditionFailedError();
        }
        return applyClientChange(fastify, existing, changeOfPatch(patch), tx);
      });
      await recordClientUpdated(fastify, request, developerId, client, fields);

      const representation = toDeveloperClient(client, await resolveClientPolicy(fastify, client));
      reply
        .header('Cache-Control', 'no-store')
        .header('ETag', developerClientEntityTag(representation));
      return reply.send(representation);
    }
  );

  typed.delete(
    '/clients/:clientId',
    {
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.delete',
        description:
          "Delete one of the token's developer's OAuth clients. It can no longer authenticate. A client of another developer is 404.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'write',
        'x-qauth-permission': 'clients.write',
        'x-qauth-errors': [400, 401, 404],
        params: clientParamsSchema,
        response: { 204: z.null() },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      await deleteDeveloperClient(fastify, request, developerId, request.params.clientId);
      reply.code(204);
      return reply.send(null);
    }
  );

  typed.post(
    '/clients/:clientId/regenerate-secret',
    {
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.regenerateSecret',
        description:
          "Issue a new `client_secret` for one of the token's developer's confidential clients. The previous secret stops working at once; this answer carries the new one once. A public client has no secret (400). A client of another developer is 404.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'write',
        'x-qauth-permission': 'clients.write',
        'x-qauth-errors': [400, 401, 404],
        params: clientParamsSchema,
        response: { 200: regeneratedDeveloperClientSchema },
      },
      // Regeneration runs an argon2id hash, as create does.
      config: { surface: 'api', rateLimit: hashingRateLimit() },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { client, policy, clientSecret } = await regenerateDeveloperClientSecret(
        fastify,
        request,
        developerId,
        request.params.clientId
      );
      const representation = toDeveloperClient(client, policy);
      reply
        .header('Cache-Control', 'no-store')
        .header('Pragma', 'no-cache')
        .header('ETag', developerClientEntityTag(representation));
      return reply.send({ ...representation, client_secret: clientSecret });
    }
  );
}
