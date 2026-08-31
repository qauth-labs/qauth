import { JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { listConsentsForUser, revokeConsentForUser } from '../../helpers/consent-management';

/**
 * Consent management for the developer portal (issue #366).
 *
 * WHY THIS EXISTS ALONGSIDE `routes/consents`.
 *
 * `/consents` authenticates with the `__Host-qauth_session` cookie, which only
 * the auth-server's own hosted UI at `/ui/login` ever sets. A developer who
 * signs in through the portal holds `__Host-qauth_portal_session` instead, and
 * could not send the auth-server's cookie cross-origin even if they had one:
 * it is `SameSite=Lax`, which permits top-level navigations, not `fetch()`
 * subresource requests. A default production deployment also resolves CORS
 * `origin` to `false`, blocking the call outright. The portal's consent screen
 * was therefore 401 for its only intended user.
 *
 * These endpoints take the same credential the portal already holds for
 * `/api/clients` — a developer Bearer access token — so the portal reaches them
 * the way it reaches everything else: from a TanStack Start server function,
 * with the token never leaving the server.
 *
 * NO CSRF TOKEN, DELIBERATELY. `/consents` requires one because a cookie is
 * ambient authority a cross-site page can make the browser attach. A Bearer
 * token is not: it has to be put on the request by code that already holds it,
 * so there is nothing for a CSRF token to add here. This is the same posture as
 * every other `/api/*` route.
 *
 * Ownership and auditing are shared with `/consents` through
 * `helpers/consent-management`, so the two surfaces cannot drift on the part
 * that matters.
 */
export const autoPrefix = '/api/consents';

const consentRowSchema = z.object({
  id: z.string(),
  clientId: z.string(),
  clientName: z.string(),
  scopes: z.array(z.string()),
  grantedAt: z.number(),
});

const listResponseSchema = z.object({
  consents: z.array(consentRowSchema),
});

/**
 * The authenticated developer's `users.id`.
 *
 * `fastify.requireJwt` has already rejected a missing or invalid token by the
 * time a handler runs, so an absent `sub` here is an internal invariant
 * violation rather than a client error — thrown as `JWTInvalidError` (401)
 * rather than trusted, matching `/api/clients`'s `requireDeveloperId`.
 */
function requireUserId(request: FastifyRequest): string {
  const sub = request.jwtPayload?.sub;
  if (!sub) {
    throw new JWTInvalidError();
  }
  return sub;
}

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          'List the active OAuth consents belonging to the authenticated user. Requires a developer Bearer access token. Drives the developer portal revocation screen (issue #366).',
        tags: ['Consents'],
        response: { 200: listResponseSchema },
      },
    },
    async (request, reply) => {
      // Per-user data; keep it out of any shared or proxy cache, matching
      // `/api/clients`.
      reply.header('Cache-Control', 'no-store');
      const consents = await listConsentsForUser(fastify, requireUserId(request));
      return reply.send({ consents });
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/:id',
    {
      preHandler: fastify.requireJwt,
      schema: {
        description:
          "Revoke one of the authenticated user's OAuth consents. Returns 404 if the consent does not exist or belongs to another user, so the API never reveals that another user's consent id exists. Requires a developer Bearer access token.",
        tags: ['Consents'],
        params: z.object({ id: z.string().uuid() }),
        response: { 204: z.null() },
      },
    },
    async (request, reply) => {
      const { id } = request.params as { id: string };
      await revokeConsentForUser(fastify, request, requireUserId(request), id);
      reply.code(204);
      return reply.send(null);
    }
  );
}
