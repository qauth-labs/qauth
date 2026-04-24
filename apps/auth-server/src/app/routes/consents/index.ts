import { BadRequestError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { resolveBrowserSession } from '../../helpers/browser-session';

/**
 * Consent management JSON API (issue #150).
 *
 * Both endpoints require a valid `__Host-qauth_session` cookie; there is
 * no Bearer-token path here because consent is inherently a user-centric
 * operation and all callers are the developer portal (same-origin) or a
 * future first-party settings UI.
 *
 *   GET    /consents           — list the active consents for the current user
 *   DELETE /consents/:id       — revoke one by id (ownership-checked)
 */

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

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/consents',
    {
      schema: {
        description:
          'List the active OAuth consents for the currently signed-in user. Drives the developer portal revocation screen (issue #150).',
        tags: ['Consents'],
        response: { 200: listResponseSchema },
      },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.code(401);
        return reply.send({ consents: [] });
      }

      const rows = await fastify.repositories.oauthConsents.listActiveForUser(session.userId);

      // N+1 is fine at the scale of "consents a user has granted". If this
      // ever becomes a problem, add a joined `listActiveForUserWithClient`
      // repo method.
      const consents = await Promise.all(
        rows.map(async (row) => {
          const client = await fastify.repositories.oauthClients.findById(row.oauthClientId);
          return {
            id: row.id,
            clientId: client?.clientId ?? 'unknown',
            clientName: client?.name ?? 'Unknown application',
            scopes: row.scopes,
            grantedAt: row.grantedAt,
          };
        })
      );

      return reply.send({ consents });
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/consents/:id',
    {
      schema: {
        description: 'Revoke an OAuth consent row owned by the currently signed-in user.',
        tags: ['Consents'],
        params: z.object({ id: z.string().uuid() }),
        response: { 204: z.null() },
      },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.code(401);
        return reply.send(null);
      }

      const { id } = request.params as { id: string };

      // Ownership check — we must not allow a user to revoke another
      // user's consent, and `revoke()` by id alone cannot enforce that.
      const rows = await fastify.repositories.oauthConsents.listActiveForUser(session.userId);
      const owned = rows.find((r) => r.id === id);
      if (!owned) {
        throw new NotFoundError('OAuthConsent', id);
      }

      try {
        await fastify.repositories.oauthConsents.revoke(id);
      } catch (err) {
        if (err instanceof NotFoundError) {
          // Raced with another tab — treat as idempotent success.
        } else if (err instanceof BadRequestError) {
          throw err;
        } else {
          throw err;
        }
      }

      await fastify.repositories.auditLogs.create({
        userId: session.userId,
        oauthClientId: owned.oauthClientId,
        event: 'oauth.consent.revoked',
        eventType: 'auth',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: { consentId: id },
      });

      reply.code(204);
      return reply.send(null);
    }
  );
}
