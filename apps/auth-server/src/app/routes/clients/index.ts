import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { listClientsResponseSchema } from '../../schemas/clients';

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
 * and manage their own clients.
 *
 *   GET /api/clients — list the authenticated developer's OAuth clients
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
}
