import { randomBytes, randomUUID } from 'node:crypto';

import { BadRequestError, JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { validateRedirectUri } from '../../helpers/dynamic-client-registration';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import {
  clientSchema,
  type CreateClientRequest,
  createClientRequestSchema,
  createClientResponseSchema,
  listClientsResponseSchema,
  regenerateSecretResponseSchema,
  type UpdateClientRequest,
  updateClientRequestSchema,
} from '../../schemas/clients';

/**
 * The shape of a single `oauth_clients` row as returned by the repository.
 * Derived from the decorator type so we stay decoupled from
 * `@qauth-labs/infra-db` (auth-server depends on it only transitively via
 * `@qauth-labs/fastify-plugin-db`), matching the boundary that
 * `helpers/client-auth.ts` keeps with its `OAuthClientLike` type.
 */
type OAuthClientRow = Awaited<
  ReturnType<FastifyInstance['repositories']['oauthClients']['listByDeveloper']>
>[number];

/**
 * Client-management JSON API (Phase 2.2, task 2.2.1 — issue #85).
 *
 * This module is the shared foundation for the whole T2 client-management
 * surface (#85 list, #86 create, #87 get-one, #88 update, #89 delete,
 * #90 regenerate-secret). It is mounted at `/api/clients` via the
 * `autoPrefix` export below — `@fastify/autoload` honours `autoPrefix` over
 * the directory-derived prefix, so sibling routes added here register
 * against the resource root (`/`, `/:id`, `/:id/secret`, …) and land under
 * `/api/clients`.
 *
 * Auth model
 * ----------
 * Every endpoint requires a developer access token via `fastify.requireJwt`
 * (Bearer JWT), mirroring `/oauth/userinfo`. This is the same credential the
 * developer portal already holds: the portal stores the access token from the
 * login flow and sends it as `Authorization: Bearer <token>`. `requireJwt`
 * throws `JWTInvalidError` (HTTP 401) for a missing/malformed/invalid token,
 * so unauthenticated callers never reach a handler.
 *
 * `request.jwtPayload.sub` is the developer's `users.id`. Ownership is scoped
 * strictly by `oauth_clients.developer_id`, so a developer can only ever see
 * and manage their own clients. A client that exists but is owned by another
 * developer is reported as **404** (not 403) so the API never leaks the
 * existence of clients the caller does not own.
 *
 *   GET    /api/clients                       — list the developer's clients (#85)
 *   POST   /api/clients                       — create a client (#86)
 *   GET    /api/clients/:id                   — get one owned client (#87)
 *   PATCH  /api/clients/:id                   — update mutable fields (#88)
 *   DELETE /api/clients/:id                   — delete a client (#89)
 *   POST   /api/clients/:id/regenerate-secret — issue a new secret (#90)
 */

// `@fastify/autoload` mounts this module under `/api/clients` regardless of
// the `clients/` directory name. Keep route paths resource-relative.
export const autoPrefix = '/api/clients';

// `oauth_clients.developer_id` is a UUID column. `request.jwtPayload.sub` is a
// developer's `users.id` (a UUID) for user tokens, but for the
// `client_credentials` grant `sub` equals the `client_id` — an opaque
// varchar, not a UUID. Querying Postgres with a non-UUID value would raise
// `22P02` (invalid input syntax for type uuid) and surface as a 500. Since a
// non-UUID subject can never own a UUID-keyed client row, treat it as
// "no clients" rather than letting it reach the database.
const uuidSubjectSchema = z.uuid();

/**
 * Project an `oauth_clients` row down to the safe fields exposed by the
 * management API. The client secret hash and any internal-only columns
 * (e.g. `dynamicRegisteredAt`, `metadata`, `realmId`) are intentionally
 * never serialized.
 */
function toClientResponse(client: OAuthClientRow) {
  return {
    id: client.id,
    clientId: client.clientId,
    name: client.name,
    description: client.description,
    redirectUris: client.redirectUris,
    scopes: client.scopes,
    grantTypes: client.grantTypes,
    responseTypes: client.responseTypes,
    tokenEndpointAuthMethod: client.tokenEndpointAuthMethod,
    enabled: client.enabled,
    requirePkce: client.requirePkce,
    createdAt: client.createdAt,
    updatedAt: client.updatedAt,
    lastUsedAt: client.lastUsedAt,
  };
}

// Path param for the single-client routes. The `id` column is a UUID; a
// malformed id can never match a row, but validating here yields a clean 400
// instead of letting a non-UUID reach Postgres (22P02 → 500).
const clientIdParamsSchema = z.object({ id: z.uuid() });

/**
 * Pull the developer's `users.id` off the verified JWT. `requireJwt` populates
 * `jwtPayload`, but we guard `sub` explicitly so we never act with an
 * undefined owner (defense-in-depth, matching the list route).
 */
function requireDeveloperId(request: { jwtPayload?: { sub?: string } }): string {
  const sub = request.jwtPayload?.sub;
  if (!sub) {
    throw new JWTInvalidError('Missing JWT payload');
  }
  return sub;
}

/**
 * Resolve a client the caller is allowed to act on, or throw `NotFoundError`.
 *
 * Ownership is enforced here for every per-client route (#87/#88/#89/#90):
 *
 * - A non-UUID subject (e.g. a `client_credentials` token whose `sub` is a
 *   `client_id`) can never own a UUID-keyed row → 404 without a DB hit.
 * - A row owned by a different developer is reported as **404, not 403**, so
 *   the API never confirms the existence of clients the caller does not own
 *   (avoids enumeration; OWASP API1/A01 BOLA).
 */
async function resolveOwnedClient(
  fastify: FastifyInstance,
  developerId: string,
  id: string
): Promise<OAuthClientRow> {
  if (!uuidSubjectSchema.safeParse(developerId).success) {
    throw new NotFoundError('OAuthClient', id);
  }

  const client = await fastify.repositories.oauthClients.findById(id);
  if (!client || client.developerId !== developerId) {
    throw new NotFoundError('OAuthClient', id);
  }
  return client;
}

/**
 * Enforce OAuth 2.1 / RFC 7591 grant_type ⇄ response_type consistency, the
 * same invariants `validateAndNormalize` applies to dynamic registration:
 *
 * - `authorization_code` requires the `code` response type.
 * - `response_types` without `authorization_code` is unsupported.
 * - `client_credentials` cannot be a public client (`none`) — a public client
 *   holds no secret and so cannot authenticate at the token endpoint
 *   (RFC 6749 §4.4).
 *
 * Throws `BadRequestError` (→ HTTP 400) on any violation. Each call site has
 * already resolved the effective grant/response/auth values (request value or
 * persisted value for partial updates).
 */
function assertGrantResponseConsistency(input: {
  grantTypes: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: string;
}): void {
  const { grantTypes, responseTypes, tokenEndpointAuthMethod } = input;

  if (grantTypes.includes('authorization_code') && !responseTypes.includes('code')) {
    throw new BadRequestError('authorization_code grant requires the "code" response type');
  }
  if (!grantTypes.includes('authorization_code') && responseTypes.length > 0) {
    throw new BadRequestError('response_types without authorization_code grant is not supported');
  }
  if (tokenEndpointAuthMethod === 'none' && grantTypes.includes('client_credentials')) {
    throw new BadRequestError(
      'client_credentials grant requires a confidential client (token_endpoint_auth_method must not be "none")'
    );
  }
}

/**
 * Generate a fresh 32-byte (256-bit) client secret and its argon2id hash.
 * Returns both so the plaintext can be surfaced exactly once in the response
 * while only the hash is ever persisted. The plaintext is never logged.
 */
async function generateClientSecret(
  fastify: FastifyInstance
): Promise<{ plaintext: string; hash: string }> {
  const plaintext = randomBytes(32).toString('hex');
  const hash = await fastify.passwordHasher.hashPassword(plaintext);
  return { plaintext, hash };
}

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          'List the OAuth clients owned by the authenticated developer. Scoped by oauth_clients.developer_id. Requires a developer Bearer access token. Never returns the client secret. (Phase 2.2, issue #85.)',
        tags: ['Clients'],
        security: [{ bearerAuth: [] }],
        response: { 200: listClientsResponseSchema },
      },
    },
    async (request, reply) => {
      const payload = request.jwtPayload;
      if (!payload || !payload.sub) {
        // Defense-in-depth: requireJwt populates jwtPayload, but guard the
        // sub explicitly so we never query with an undefined owner.
        throw new JWTInvalidError('Missing JWT payload');
      }

      const developerId = payload.sub;

      // A non-UUID subject (e.g. a client_credentials token whose `sub` is a
      // `client_id`) can never own a client row, so short-circuit to an empty
      // list instead of issuing a query that Postgres would reject with 22P02.
      if (!uuidSubjectSchema.safeParse(developerId).success) {
        return reply.send({ clients: [] });
      }

      const rows = await fastify.repositories.oauthClients.listByDeveloper(developerId);

      return reply.send({ clients: rows.map(toClientResponse) });
    }
  );

  // ── POST /api/clients — create a client (#86) ───────────────────────────
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          'Create an OAuth client owned by the authenticated developer. The server generates the client_id and (for confidential clients) a client_secret; the plaintext secret is returned in THIS response only and never again. Requires a developer Bearer access token. (Phase 2.2, issue #86.)',
        tags: ['Clients'],
        security: [{ bearerAuth: [] }],
        body: createClientRequestSchema,
        response: { 201: createClientResponseSchema },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);

      // `developer_id` is a UUID column; a non-UUID subject (client_credentials
      // token) cannot own a client and must not be allowed to create one.
      if (!uuidSubjectSchema.safeParse(developerId).success) {
        throw new JWTInvalidError('A user access token is required to create clients');
      }

      const body = request.body as CreateClientRequest;

      const grantTypes = body.grantTypes ?? ['authorization_code', 'refresh_token'];
      const responseTypes = body.responseTypes ?? ['code'];
      const tokenEndpointAuthMethod = body.tokenEndpointAuthMethod ?? 'none';

      for (const uri of body.redirectUris) {
        validateRedirectUri(uri);
      }
      assertGrantResponseConsistency({ grantTypes, responseTypes, tokenEndpointAuthMethod });

      const realm = await getOrCreateDefaultRealm(fastify);
      const clientId = randomUUID();

      // Confidential clients get a real secret; public clients
      // (auth method `none`) store a non-verifiable sentinel hash so the
      // NOT NULL column is satisfied without minting a usable secret — and so
      // the hash length never leaks the client type (matches /oauth/register).
      const isPublic = tokenEndpointAuthMethod === 'none';
      let plaintextSecret: string | undefined;
      let clientSecretHash: string;
      if (isPublic) {
        clientSecretHash = await fastify.passwordHasher.hashPassword(
          randomBytes(32).toString('hex')
        );
      } else {
        const secret = await generateClientSecret(fastify);
        plaintextSecret = secret.plaintext;
        clientSecretHash = secret.hash;
      }

      const created = await fastify.repositories.oauthClients.create({
        realmId: realm.id,
        clientId,
        clientSecretHash,
        name: body.name,
        description: body.description ?? null,
        redirectUris: body.redirectUris,
        scopes: body.scopes,
        grantTypes,
        responseTypes,
        tokenEndpointAuthMethod,
        // Project-wide default: require PKCE for all clients (OAuth 2.1 §4.1.3
        // / RFC 9700). Public clients MUST; confidential clients SHOULD.
        requirePkce: true,
        enabled: true,
        developerId,
      });

      await fastify.repositories.auditLogs.create({
        userId: developerId,
        oauthClientId: created.id,
        event: 'oauth.client.created',
        eventType: 'client',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: {
          clientId,
          isPublic,
          grantTypes,
          tokenEndpointAuthMethod,
        },
      });

      // Response carries the plaintext secret once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.code(201).send({
        ...toClientResponse(created),
        ...(plaintextSecret ? { clientSecret: plaintextSecret } : {}),
      });
    }
  );

  // ── GET /api/clients/:id — get one owned client (#87) ───────────────────
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/:id',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "Get one of the authenticated developer's OAuth clients by id. Returns 404 if the client does not exist or is owned by another developer (no existence enumeration). Never returns the client secret. (Phase 2.2, issue #87.)",
        tags: ['Clients'],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 200: clientSchema },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };

      const client = await resolveOwnedClient(fastify, developerId, id);

      return reply.send(toClientResponse(client));
    }
  );

  // ── PATCH /api/clients/:id — update mutable fields (#88) ─────────────────
  fastify.withTypeProvider<ZodTypeProvider>().patch(
    '/:id',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "Update mutable fields of one of the developer's OAuth clients (name, description, redirectUris, scopes, grantTypes, responseTypes, tokenEndpointAuthMethod, enabled). client_id and client_secret are immutable here. Returns 404 if the client does not exist or is owned by another developer. (Phase 2.2, issue #88.)",
        tags: ['Clients'],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        body: updateClientRequestSchema,
        response: { 200: clientSchema },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };
      const body = request.body as UpdateClientRequest;

      const existing = await resolveOwnedClient(fastify, developerId, id);

      // Validate the *effective* configuration: take each field from the
      // request when present, else fall back to the persisted value. This
      // catches an update that would leave the client in an inconsistent
      // state (e.g. removing authorization_code while keeping response_types).
      const grantTypes = body.grantTypes ?? existing.grantTypes;
      const responseTypes = body.responseTypes ?? existing.responseTypes;
      const tokenEndpointAuthMethod =
        body.tokenEndpointAuthMethod ?? existing.tokenEndpointAuthMethod;

      if (body.redirectUris) {
        for (const uri of body.redirectUris) {
          validateRedirectUri(uri);
        }
      }
      assertGrantResponseConsistency({ grantTypes, responseTypes, tokenEndpointAuthMethod });

      const updated = await fastify.repositories.oauthClients.update(id, {
        ...(body.name !== undefined ? { name: body.name } : {}),
        ...(body.description !== undefined ? { description: body.description } : {}),
        ...(body.redirectUris !== undefined ? { redirectUris: body.redirectUris } : {}),
        ...(body.scopes !== undefined ? { scopes: body.scopes } : {}),
        ...(body.grantTypes !== undefined ? { grantTypes: body.grantTypes } : {}),
        ...(body.responseTypes !== undefined ? { responseTypes: body.responseTypes } : {}),
        ...(body.tokenEndpointAuthMethod !== undefined
          ? { tokenEndpointAuthMethod: body.tokenEndpointAuthMethod }
          : {}),
        ...(body.enabled !== undefined ? { enabled: body.enabled } : {}),
      });

      await fastify.repositories.auditLogs.create({
        userId: developerId,
        oauthClientId: updated.id,
        event: 'oauth.client.updated',
        eventType: 'client',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: { clientId: updated.clientId, fields: Object.keys(body) },
      });

      return reply.send(toClientResponse(updated));
    }
  );

  // ── DELETE /api/clients/:id — delete a client (#89) ─────────────────────
  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/:id',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "Delete one of the developer's OAuth clients. Returns 404 if the client does not exist or is owned by another developer. After deletion the client can no longer authenticate. (Phase 2.2, issue #89.)",
        tags: ['Clients'],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 204: z.null() },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };

      // Ownership-check before deleting: delete-by-id alone cannot enforce it.
      const existing = await resolveOwnedClient(fastify, developerId, id);

      await fastify.repositories.oauthClients.delete(id);

      await fastify.repositories.auditLogs.create({
        userId: developerId,
        oauthClientId: existing.id,
        event: 'oauth.client.deleted',
        eventType: 'client',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: { clientId: existing.clientId },
      });

      reply.code(204);
      return reply.send(null);
    }
  );

  // ── POST /api/clients/:id/regenerate-secret — issue a new secret (#90) ──
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/:id/regenerate-secret',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "Issue a new client_secret for one of the developer's OAuth clients. The previous secret is invalidated immediately and the new plaintext secret is returned in THIS response only. Returns 404 if the client does not exist or is owned by another developer; 400 for a public client that has no secret. (Phase 2.2, issue #90.)",
        tags: ['Clients'],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 200: regenerateSecretResponseSchema },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { id } = request.params as { id: string };

      const existing = await resolveOwnedClient(fastify, developerId, id);

      // A public client (auth method `none`) holds no usable secret, so
      // regeneration is meaningless and would mint a credential the client
      // cannot present. Reject rather than silently confidential-ising it.
      if (existing.tokenEndpointAuthMethod === 'none') {
        throw new BadRequestError(
          'Cannot regenerate a secret for a public client (token_endpoint_auth_method is "none")'
        );
      }

      const { plaintext, hash } = await generateClientSecret(fastify);

      const updated = await fastify.repositories.oauthClients.update(id, {
        clientSecretHash: hash,
      });

      await fastify.repositories.auditLogs.create({
        userId: developerId,
        oauthClientId: updated.id,
        event: 'oauth.client.secret_regenerated',
        eventType: 'client',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: { clientId: updated.clientId },
      });

      // Response carries the plaintext secret once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.send({ ...toClientResponse(updated), clientSecret: plaintext });
    }
  );
}
