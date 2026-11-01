import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { readPage } from '../../api-conventions/cursor';
import { pageQuerySchema, pageSchema } from '../../api-conventions/paging';
import { rfc3339, rfc3339OrNull } from '../../api-conventions/time';
import {
  type ApiKeyRow,
  mintDeveloperApiKey,
  revokeDeveloperApiKey,
} from '../../helpers/developer-api-keys';
import { requireDeveloperId, resolveOwnedClient } from '../../helpers/developer-clients';
import { requireFamilyToken } from '../../helpers/family-token';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import {
  createDeveloperApiKeyRequestSchema,
  developerApiKeySchema,
  mintedDeveloperApiKeySchema,
} from '../../schemas/developer-api';

/**
 * The developer API's static API keys (ADR-008 §6, #524), under a client the
 * developer owns:
 *
 *   GET    /clients/{clientId}/api-keys          — list, masked, a page at a time
 *   POST   /clients/{clientId}/api-keys          — mint (environment-gated)
 *   DELETE /clients/{clientId}/api-keys/{keyId}  — revoke (soft delete)
 *
 * A client owned by another developer, and a key of another client, are 404.
 */

const clientParamsSchema = z.object({ clientId: z.uuid() });
const keyParamsSchema = z.object({ clientId: z.uuid(), keyId: z.uuid() });

const TAGS = ['Developer API'];

/** A key's masked representation: never the key, never its hash. */
function toDeveloperApiKey(row: ApiKeyRow) {
  return {
    id: row.id,
    clientId: row.clientId,
    name: row.name,
    prefix: row.prefix,
    last4: row.last4,
    createdAt: rfc3339(row.createdAt),
    lastUsedAt: rfc3339OrNull(row.lastUsedAt),
    revokedAt: rfc3339OrNull(row.revokedAt),
  };
}

export function registerDeveloperApiKeyRoutes(fastify: FastifyInstance): void {
  const guard = requireFamilyToken('developer', { subjects: ['user'] });
  const typed = fastify.withTypeProvider<ZodTypeProvider>();

  typed.get(
    '/clients/:clientId/api-keys',
    {
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.apiKeys.list',
        description:
          "List the static API keys of one of the token's developer's clients, newest first, one page at a time: masked fields only, revoked keys included. A client of another developer is 404.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'read',
        'x-qauth-permission': 'clients.apiKeys.read',
        'x-qauth-errors': [400, 401, 404],
        params: clientParamsSchema,
        querystring: pageQuerySchema,
        response: { 200: pageSchema(developerApiKeySchema) },
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
      const page = await readPage(
        {
          // Bound to the client: a cursor of another client's list is refused.
          list: `developer.clients.${client.id}.apiKeys`,
          limit: request.query.limit,
          cursor: request.query.cursor,
          position: (row: ApiKeyRow) => ({ at: row.createdAt, id: row.id }),
          item: toDeveloperApiKey,
        },
        (keyset) => fastify.repositories.apiKeys.pageByClient(client.realmId, client.id, keyset)
      );
      reply.header('Cache-Control', 'no-store');
      return reply.send(page);
    }
  );

  typed.post(
    '/clients/:clientId/api-keys',
    {
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.apiKeys.create',
        description:
          "Mint a static API key for one of the token's developer's clients. Permitted only while the client's effective environment is development (ADR-008 §6); any other is 403 and uses the client_credentials grant. The plaintext `key` is in this answer once and never again. A client of another developer is 404.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'write',
        'x-qauth-permission': 'clients.apiKeys.write',
        'x-qauth-errors': [400, 401, 403, 404],
        params: clientParamsSchema,
        body: createDeveloperApiKeyRequestSchema,
        response: { 201: mintedDeveloperApiKeySchema },
      },
      config: {
        surface: 'api',
        // Minting runs an argon2id hash on every call: capped per address.
        rateLimit: {
          max: env.REGISTER_CLIENT_RATE_LIMIT,
          timeWindow: env.REGISTER_CLIENT_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
        },
      },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const { apiKey, key } = await mintDeveloperApiKey(
        fastify,
        request,
        developerId,
        request.params.clientId,
        request.body.name
      );
      // The plaintext key is carried once — MUST NOT be cached.
      reply.header('Cache-Control', 'no-store').header('Pragma', 'no-cache');
      return reply.code(201).send({ ...toDeveloperApiKey(apiKey), key });
    }
  );

  typed.delete(
    '/clients/:clientId/api-keys/:keyId',
    {
      preValidation: guard,
      schema: {
        operationId: 'developer.clients.apiKeys.delete',
        description:
          "Revoke one static API key of one of the token's developer's clients, and answer it with `revokedAt` set. Idempotent: the key is kept, revoked, and never authenticates again. A client or key of another developer is 404.",
        tags: TAGS,
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'stable',
        'x-qauth-class': 'write',
        'x-qauth-permission': 'clients.apiKeys.write',
        'x-qauth-errors': [400, 401, 404],
        params: keyParamsSchema,
        response: { 200: developerApiKeySchema },
      },
      config: { surface: 'api' },
    },
    async (request, reply) => {
      const developerId = requireDeveloperId(request);
      const revoked = await revokeDeveloperApiKey(
        fastify,
        request,
        developerId,
        request.params.clientId,
        request.params.keyId
      );
      return reply.send(toDeveloperApiKey(revoked));
    }
  );
}
