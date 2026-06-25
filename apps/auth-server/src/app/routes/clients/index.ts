import { randomBytes, randomUUID } from 'node:crypto';

import { BadRequestError, JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
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
 * Enforce OAuth 2.1 / RFC 7591 grant_type ⇄ response_type ⇄ redirect_uri
 * consistency, the same invariants `validateAndNormalize` applies to dynamic
 * registration:
 *
 * - `authorization_code` requires the `code` response type.
 * - `response_types` without `authorization_code` is unsupported.
 * - `client_credentials` cannot be a public client (`none`) — a public client
 *   holds no secret and so cannot authenticate at the token endpoint
 *   (RFC 6749 §4.4).
 * - A user-involving grant (`authorization_code` / `refresh_token`) requires at
 *   least one `redirect_uri`; without one the client can never complete a
 *   user-agent flow (mirrors DCR's `redirect_uris is required …` rejection).
 *
 * Throws `BadRequestError` (→ HTTP 400) on any violation. Each call site has
 * already resolved the effective grant/response/auth/redirect values (request
 * value or persisted value for partial updates).
 */
function assertGrantResponseConsistency(input: {
  grantTypes: string[];
  responseTypes: string[];
  tokenEndpointAuthMethod: string;
  redirectUris: string[];
}): void {
  const { grantTypes, responseTypes, tokenEndpointAuthMethod, redirectUris } = input;

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
  const userInvolving =
    grantTypes.includes('authorization_code') || grantTypes.includes('refresh_token');
  if (userInvolving && redirectUris.length === 0) {
    throw new BadRequestError(
      'redirect_uris is required for grants that involve a user-agent (authorization_code / refresh_token)'
    );
  }
}

/**
 * Resolve the realm's effective dynamic-registration scope allowlist, seeding
 * it from `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` on first use exactly as
 * `/oauth/register` does. The REST create/update paths reuse this same policy
 * so a developer cannot self-grant a scope through the management API that the
 * realm would refuse at dynamic registration — keeping the two
 * client-creation paths consistent. Seeding is best-effort: a racing write
 * never blocks the request.
 */
async function resolveRealmAllowedScopes(
  fastify: FastifyInstance,
  realm: { id: string; dynamicRegistrationAllowedScopes?: string[] | null }
): Promise<string[]> {
  let allowedScopes = realm.dynamicRegistrationAllowedScopes ?? [];
  if (allowedScopes.length === 0 && env.DEFAULT_DYNAMIC_REGISTRATION_SCOPES.length > 0) {
    allowedScopes = [...env.DEFAULT_DYNAMIC_REGISTRATION_SCOPES];
    try {
      await fastify.repositories.realms.update(realm.id, {
        dynamicRegistrationAllowedScopes: allowedScopes,
      });
    } catch (err) {
      fastify.log.warn(
        { err, realmId: realm.id },
        'Failed to persist default dynamic_registration_allowed_scopes'
      );
    }
  }
  return allowedScopes;
}

/**
 * Cap requested `scopes` against the realm allowlist, rejecting anything
 * outside it (RFC 7591 `invalid_client_metadata` equivalent). Empty allowlist
 * means no custom scopes are permitted. Throws `BadRequestError` → HTTP 400.
 */
function assertScopesAllowed(requested: string[], realmAllowedScopes: string[]): void {
  const disallowed = requested.filter((s) => !realmAllowedScopes.includes(s));
  if (disallowed.length > 0) {
    throw new BadRequestError(`scope not permitted: ${disallowed.join(' ')}`);
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

/**
 * Audit log shape for a client-management event (subset of the audit_logs
 * repository's create payload).
 */
type ClientAuditEntry = Parameters<FastifyInstance['repositories']['auditLogs']['create']>[0];

/**
 * Write an audit entry best-effort: a logging failure MUST NOT propagate.
 *
 * This matters most on the secret-bearing paths (create / regenerate): the
 * client row (or rotated secret hash) is already committed, so throwing here
 * would 500 *after* the only copy of the plaintext secret was generated,
 * leaving the developer with a client they can never authenticate. We log the
 * failure and continue so the one-time secret still reaches the response.
 */
async function auditBestEffort(fastify: FastifyInstance, entry: ClientAuditEntry): Promise<void> {
  try {
    await fastify.repositories.auditLogs.create(entry);
  } catch (err) {
    fastify.log.warn(
      { err, event: entry.event, oauthClientId: entry.oauthClientId },
      'Failed to write client-management audit log (non-fatal)'
    );
  }
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
      config: {
        // Create runs an argon2id hash on every call (confidential clients hash
        // the real secret; public clients hash a sentinel), so an authenticated
        // caller could otherwise burn CPU at the global default rate. Cap it
        // per-IP at the same budget as /oauth/register, whose comment notes the
        // hash makes "a burst-proof cap mandatory".
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
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
      // Zod applies `.default([])`, but default defensively so the handler is
      // also correct when invoked without the schema layer (unit tests).
      const redirectUris = body.redirectUris ?? [];
      const scopes = body.scopes ?? [];

      for (const uri of redirectUris) {
        validateRedirectUri(uri);
      }
      assertGrantResponseConsistency({
        grantTypes,
        responseTypes,
        tokenEndpointAuthMethod,
        redirectUris,
      });

      const realm = await getOrCreateDefaultRealm(fastify);

      // Cap requested scopes against the realm policy *before* hashing — a
      // policy-violating request must not pay the argon2id cost or persist.
      const allowedScopes = await resolveRealmAllowedScopes(fastify, realm);
      assertScopesAllowed(scopes, allowedScopes);

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
        redirectUris,
        scopes,
        grantTypes,
        responseTypes,
        tokenEndpointAuthMethod,
        // Project-wide default: require PKCE for all clients (OAuth 2.1 §4.1.3
        // / RFC 9700). Public clients MUST; confidential clients SHOULD.
        requirePkce: true,
        enabled: true,
        developerId,
      });

      // Best-effort: the client (and its secret hash) is already committed, so
      // a failing audit write must not 500 and lose the one-time plaintext.
      await auditBestEffort(fastify, {
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
      // state (e.g. removing authorization_code while keeping response_types,
      // or dropping the last redirect_uri from an authorization_code client).
      const grantTypes = body.grantTypes ?? existing.grantTypes;
      const responseTypes = body.responseTypes ?? existing.responseTypes;
      const tokenEndpointAuthMethod =
        body.tokenEndpointAuthMethod ?? existing.tokenEndpointAuthMethod;
      const redirectUris = body.redirectUris ?? existing.redirectUris;

      if (body.redirectUris) {
        for (const uri of body.redirectUris) {
          validateRedirectUri(uri);
        }
      }
      assertGrantResponseConsistency({
        grantTypes,
        responseTypes,
        tokenEndpointAuthMethod,
        redirectUris,
      });

      // Cap newly requested scopes against the client's realm policy, the same
      // allowlist dynamic registration enforces — a developer must not widen
      // scopes via PATCH beyond what the realm permits.
      if (body.scopes !== undefined) {
        const realm = await fastify.repositories.realms.findById(existing.realmId);
        const allowedScopes = realm ? await resolveRealmAllowedScopes(fastify, realm) : [];
        assertScopesAllowed(body.scopes, allowedScopes);
      }

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

      await auditBestEffort(fastify, {
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

      await auditBestEffort(fastify, {
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
      config: {
        // Regeneration always runs an argon2id hash, so it carries the same
        // CPU-DoS profile as create — cap it per-IP at the same budget.
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
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

      // Best-effort: the new secret hash is already committed and the old one
      // invalidated, so a failing audit write must not 500 and lose the
      // one-time plaintext (the client would be locked out of its own secret).
      await auditBestEffort(fastify, {
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
