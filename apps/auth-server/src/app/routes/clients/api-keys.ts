import { JWTInvalidError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { assertStaticApiKeysAllowed, generateApiKey } from '../../helpers/api-key';
import {
  apiKeySchema,
  type CreateApiKeyRequest,
  createApiKeyRequestSchema,
  createApiKeyResponseSchema,
  listApiKeysResponseSchema,
} from '../../schemas/api-keys';

/**
 * Static developer API-key management routes (ADR-008 §6, issue #97).
 *
 * Registered by `routes/clients/index.ts` so these endpoints share that
 * module's `/api/clients` autoPrefix, auth model, realm scoping, and error
 * shapes. They hang off a specific client:
 *
 *   POST   /api/clients/:clientId/api-keys           — mint a key (env-gated)
 *   GET    /api/clients/:clientId/api-keys           — list a client's keys (masked)
 *   DELETE /api/clients/:clientId/api-keys/:keyId    — revoke a key
 *
 * Auth model (identical to the client-management API): every endpoint requires
 * a developer Bearer access token via `fastify.requireJwt`; ownership is scoped
 * by `oauth_clients.developer_id`. A client owned by another developer (or a
 * non-UUID subject, e.g. a client_credentials token) is reported as 404, never
 * 403, so existence is never leaked (OWASP API1/A01 BOLA).
 *
 * The environment GATE is the heart of #97: a key may be minted ONLY while the
 * client resolves to `staticApiKeysAllowed` via
 * `resolveEnvironmentPolicy(client, realm)` — fail-safe, so an unset /
 * `production` client is refused with 403 and steered to `client_credentials`.
 * The gate lives entirely in `helpers/api-key.ts`; this module never re-derives
 * the rule from the raw `environment` column.
 */

// A user token's `sub` is a UUID `users.id`; a client_credentials token's `sub`
// is an opaque `client_id`. Querying a UUID column with a non-UUID would raise
// Postgres 22P02 → 500, and such a subject can never own a UUID-keyed client,
// so we short-circuit it to 404 before any DB hit.
const uuidSubjectSchema = z.uuid();

const clientIdParamsSchema = z.object({ clientId: z.uuid() });
const keyParamsSchema = z.object({ clientId: z.uuid(), keyId: z.uuid() });

/** The shape of a single `api_keys` row as returned by the repository. */
type ApiKeyRow = Awaited<
  ReturnType<FastifyInstance['repositories']['apiKeys']['listByClient']>
>[number];

/**
 * Project an `api_keys` row to the masked, non-secret fields exposed by the
 * API. The `keyHash` and any internal columns are never serialized.
 */
function toApiKeyResponse(row: ApiKeyRow) {
  return {
    id: row.id,
    clientId: row.clientId,
    name: row.name,
    prefix: row.prefix,
    last4: row.last4,
    createdAt: row.createdAt,
    lastUsedAt: row.lastUsedAt,
    revokedAt: row.revokedAt,
  };
}

/** Pull the developer's `users.id` off the verified JWT (defense-in-depth). */
function requireDeveloperId(request: { jwtPayload?: { sub?: string } }): string {
  const sub = request.jwtPayload?.sub;
  if (!sub) {
    throw new JWTInvalidError('Missing JWT payload');
  }
  return sub;
}

/**
 * Resolve a client the caller owns, or throw 404. Mirrors
 * `resolveOwnedClient` in `index.ts`: a non-UUID subject and a client owned by
 * another developer are both reported as 404 (no existence enumeration).
 */
async function resolveOwnedClient(fastify: FastifyInstance, developerId: string, clientId: string) {
  if (!uuidSubjectSchema.safeParse(developerId).success) {
    throw new NotFoundError('OAuthClient', clientId);
  }
  const client = await fastify.repositories.oauthClients.findById(clientId);
  if (!client || client.developerId !== developerId) {
    throw new NotFoundError('OAuthClient', clientId);
  }
  return client;
}

/**
 * Register the API-key routes onto an already-prefixed (`/api/clients`)
 * encapsulated context. Called from `routes/clients/index.ts`.
 */
export async function registerApiKeyRoutes(fastify: FastifyInstance): Promise<void> {
  // ── POST /api/clients/:clientId/api-keys — mint a key (env-gated) ─────────
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/:clientId/api-keys',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "Mint a static developer API key for one of the developer's OAuth clients. ENVIRONMENT-GATED (ADR-008 §6): permitted only while the client resolves to a development environment; a staging/production (or unset-environment) client is refused with 403 and must use the OAuth client_credentials grant. The plaintext key is returned in THIS response only and never again. Returns 404 if the client does not exist or is owned by another developer. (Issue #97.)",
        tags: ['API Keys'],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        body: createApiKeyRequestSchema,
        response: { 201: createApiKeyResponseSchema },
      },
      config: {
        // Minting runs an argon2id hash on every call, so an authenticated
        // caller could otherwise burn CPU at the global default rate. Cap it
        // per-IP at the same budget as client create / regenerate-secret.
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: (req) => req.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { clientId } = request.params as { clientId: string };
      const body = request.body as CreateApiKeyRequest;

      const client = await resolveOwnedClient(fastify, developerId, clientId);

      // ENVIRONMENT GATE (ADR-008 §6): resolve the client's effective policy and
      // refuse minting (403) unless static API keys are allowed. Done BEFORE
      // hashing so a forbidden request never pays the argon2id cost or persists.
      const realm = await fastify.repositories.realms.findById(client.realmId);
      assertStaticApiKeysAllowed(client, realm ?? null);

      const generated = await generateApiKey(fastify);

      const created = await fastify.repositories.apiKeys.create({
        realmId: client.realmId,
        clientId: client.id,
        developerId,
        name: body.name,
        keyHash: generated.keyHash,
        prefix: generated.prefix,
        last4: generated.last4,
      });

      // Best-effort audit: the key (and its hash) is already committed, so a
      // failing audit write must not 500 and lose the one-time plaintext.
      try {
        await fastify.repositories.auditLogs.create({
          userId: developerId,
          oauthClientId: client.id,
          event: 'api_key.created',
          eventType: 'client',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { apiKeyId: created.id, prefix: created.prefix, clientId: client.clientId },
        });
      } catch (err) {
        fastify.log.warn(
          { err, apiKeyId: created.id },
          'Failed to write api_key.created audit log'
        );
      }

      // The plaintext key is carried once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.code(201).send({ ...toApiKeyResponse(created), key: generated.key });
    }
  );

  // ── GET /api/clients/:clientId/api-keys — list a client's keys (masked) ───
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/:clientId/api-keys',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "List the static API keys for one of the developer's OAuth clients. Returns masked fields only (prefix + last4) — never the key or its hash. Includes revoked keys (with revokedAt set). Returns 404 if the client does not exist or is owned by another developer. (Issue #97.)",
        tags: ['API Keys'],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 200: listApiKeysResponseSchema },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { clientId } = request.params as { clientId: string };

      const client = await resolveOwnedClient(fastify, developerId, clientId);

      const rows = await fastify.repositories.apiKeys.listByClient(client.id);
      return reply.send({ apiKeys: rows.map(toApiKeyResponse) });
    }
  );

  // ── DELETE /api/clients/:clientId/api-keys/:keyId — revoke a key ──────────
  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/:clientId/api-keys/:keyId',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "Revoke one static API key for one of the developer's OAuth clients. Idempotent soft-delete: the row is retained with revokedAt set, and a revoked key never authenticates again. Returns 404 if the client or key does not exist or is owned by another developer. (Issue #97.)",
        tags: ['API Keys'],
        security: [{ bearerAuth: [] }],
        params: keyParamsSchema,
        response: { 200: apiKeySchema },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { clientId, keyId } = request.params as { clientId: string; keyId: string };

      const client = await resolveOwnedClient(fastify, developerId, clientId);

      // The key must belong to the resolved (owned) client; otherwise 404 so a
      // key id is never confirmed across ownership boundaries.
      const existing = await fastify.repositories.apiKeys.findById(keyId);
      if (!existing || existing.clientId !== client.id) {
        throw new NotFoundError('ApiKey', keyId);
      }

      const revoked = await fastify.repositories.apiKeys.revoke(keyId);
      if (!revoked) {
        // Concurrent hard-delete or vanished row — treat as not found.
        throw new NotFoundError('ApiKey', keyId);
      }

      try {
        await fastify.repositories.auditLogs.create({
          userId: developerId,
          oauthClientId: client.id,
          event: 'api_key.revoked',
          eventType: 'client',
          success: true,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { apiKeyId: revoked.id, prefix: revoked.prefix, clientId: client.clientId },
        });
      } catch (err) {
        fastify.log.warn(
          { err, apiKeyId: revoked.id },
          'Failed to write api_key.revoked audit log'
        );
      }

      return reply.send(toApiKeyResponse(revoked));
    }
  );
}
