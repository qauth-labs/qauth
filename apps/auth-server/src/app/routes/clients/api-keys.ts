import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  type ApiKeyRow,
  mintDeveloperApiKey,
  revokeDeveloperApiKey,
} from '../../helpers/developer-api-keys';
import { requireDeveloperId, resolveOwnedClient } from '../../helpers/developer-clients';
import { createRequireManagementJwt } from '../../helpers/management-token';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
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
 * DEPRECATED since #524, with the rest of `/api/clients`: the developer API
 * serves them at `/developer/v1-rc.0/clients/{clientId}/api-keys`. The
 * domain logic both share is in `helpers/developer-api-keys.ts`.
 *
 * Registered by `routes/clients/index.ts` so these endpoints share that
 * module's `/api/clients` autoPrefix, auth model, realm scoping, deprecation
 * headers and error shapes. They hang off a specific client:
 *
 *   POST   /api/clients/:clientId/api-keys           — mint a key (env-gated)
 *   GET    /api/clients/:clientId/api-keys           — list a client's keys (masked)
 *   DELETE /api/clients/:clientId/api-keys/:keyId    — revoke a key
 *
 * Auth model (identical to the client-management API): every endpoint requires
 * the developer-portal management token via `createRequireManagementJwt`;
 * ownership is scoped by `oauth_clients.developer_id`. A client owned by
 * another developer (or a non-UUID subject, e.g. a client_credentials token)
 * is reported as 404, never 403, so existence is never leaked.
 */

const clientIdParamsSchema = z.object({ clientId: z.uuid() });
const keyParamsSchema = z.object({ clientId: z.uuid(), keyId: z.uuid() });

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

/**
 * Register the API-key routes onto an already-prefixed (`/api/clients`)
 * encapsulated context. Called from `routes/clients/index.ts`.
 */
export async function registerApiKeyRoutes(fastify: FastifyInstance): Promise<void> {
  const requireManagementJwt = createRequireManagementJwt(fastify);

  // ── POST /api/clients/:clientId/api-keys — mint a key (env-gated) ─────────
  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/:clientId/api-keys',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          "Mint a static developer API key for one of the developer's OAuth clients. ENVIRONMENT-GATED (ADR-008 §6): permitted only while the client resolves to a development environment; a staging/production (or unset-environment) client is refused with 403 and must use the OAuth client_credentials grant. The plaintext key is returned in THIS response only and never again. Returns 404 if the client does not exist or is owned by another developer. (Issue #97.)",
        tags: ['API Keys'],
        'x-qauth-stability': 'stable',
        deprecated: true,
        'x-qauth-errors': [400, 401, 403, 404],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        body: createApiKeyRequestSchema,
        response: { 201: createApiKeyResponseSchema },
      },
      config: {
        surface: 'api',
        // Minting runs an argon2id hash on every call, so an authenticated
        // caller could otherwise burn CPU at the global default rate. Cap it
        // per-IP at the same budget as client create / regenerate-secret.
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { clientId } = request.params as { clientId: string };
      const body = request.body as CreateApiKeyRequest;

      const { apiKey, key } = await mintDeveloperApiKey(
        fastify,
        request,
        developerId,
        clientId,
        body.name
      );

      // The plaintext key is carried once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.code(201).send({ ...toApiKeyResponse(apiKey), key });
    }
  );

  // ── GET /api/clients/:clientId/api-keys — list a client's keys (masked) ───
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/:clientId/api-keys',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          "List the static API keys for one of the developer's OAuth clients. Returns masked fields only (prefix + last4) — never the key or its hash. Includes revoked keys (with revokedAt set). Returns 404 if the client does not exist or is owned by another developer. (Issue #97.)",
        tags: ['API Keys'],
        'x-qauth-stability': 'stable',
        deprecated: true,
        'x-qauth-errors': [400, 401, 404],
        security: [{ bearerAuth: [] }],
        params: clientIdParamsSchema,
        response: { 200: listApiKeysResponseSchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { clientId } = request.params as { clientId: string };

      const client = await resolveOwnedClient(fastify, request, developerId, clientId);

      const rows = await fastify.repositories.apiKeys.listByClient(client.realmId, client.id);
      return reply.send({ apiKeys: rows.map(toApiKeyResponse) });
    }
  );

  // ── DELETE /api/clients/:clientId/api-keys/:keyId — revoke a key ──────────
  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/:clientId/api-keys/:keyId',
    {
      preHandler: requireManagementJwt,
      schema: {
        description:
          "Revoke one static API key for one of the developer's OAuth clients. Idempotent soft-delete: the row is retained with revokedAt set, and a revoked key never authenticates again. Returns 404 if the client or key does not exist or is owned by another developer. (Issue #97.)",
        tags: ['API Keys'],
        'x-qauth-stability': 'stable',
        deprecated: true,
        'x-qauth-errors': [400, 401, 404],
        security: [{ bearerAuth: [] }],
        params: keyParamsSchema,
        response: { 200: apiKeySchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { clientId, keyId } = request.params as { clientId: string; keyId: string };

      const revoked = await revokeDeveloperApiKey(fastify, request, developerId, clientId, keyId);
      return reply.send(toApiKeyResponse(revoked));
    }
  );
}
