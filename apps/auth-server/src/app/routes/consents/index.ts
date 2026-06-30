import { BadRequestError, NotFoundError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { resolveBrowserSession } from '../../helpers/browser-session';
import {
  type BrowserSessionData,
  csrfTokensEqual,
  generateCsrfToken,
} from '../../helpers/session-cookie';

/**
 * Consent management JSON API (issue #150).
 *
 * Both endpoints require a valid `__Host-qauth_session` cookie; there is
 * no Bearer-token path here because consent is inherently a user-centric
 * operation and all callers are the developer portal (same-origin) or a
 * future first-party settings UI.
 *
 * CSRF protection: `DELETE /consents/:id` is state-changing and cookie-
 * authed, so it is vulnerable to CSRF. The session-cookie is `SameSite=Lax`
 * (blocks cross-site POST/DELETE) but that is a browser control, not a token;
 * an XSS on the same origin or a future SameSite-Lax top-level navigation
 * trick could still reach it. Defense-in-depth: the GET mints (or reuses) a
 * per-session `apiCsrfToken`, returns it in the response body, and the DELETE
 * MUST echo it back via the `X-CSRF-Token` request header. The custom header
 * forces a CORS preflight (which fails for cross-origin callers without an
 * explicit CORS allowlist), and the timing-safe token comparison closes the
 * gap even for same-origin XSS-driven calls that cannot read the response.
 *
 *   GET    /consents           — list active consents + return the CSRF token
 *   DELETE /consents/:id       — revoke one by id (ownership + CSRF-checked)
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
  /** Per-session CSRF token the caller MUST echo back as `X-CSRF-Token` on DELETE. */
  csrfToken: z.string(),
});

const unauthorizedResponseSchema = z.object({
  consents: z.array(consentRowSchema),
});

/** Header name carrying the CSRF token on state-changing JSON requests. */
const CSRF_HEADER = 'x-csrf-token';

/**
 * Ensure the session carries an `apiCsrfToken`; mint + persist one if absent.
 * The token is long-lived (per session) so concurrent / multi-tab usage works.
 * Returns the token to embed in a response.
 */
async function ensureApiCsrfToken(
  fastify: FastifyInstance,
  session: BrowserSessionData
): Promise<string> {
  if (session.apiCsrfToken) return session.apiCsrfToken;
  const token = generateCsrfToken();
  await fastify.sessionUtils.setSession<BrowserSessionData>(
    session.sessionId,
    { ...session, apiCsrfToken: token },
    env.SESSION_COOKIE_TTL
  );
  return token;
}

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/consents',
    {
      schema: {
        description:
          'List the active OAuth consents for the currently signed-in user. Drives the developer portal revocation screen (issue #150). The response also carries a per-session CSRF token that the caller MUST echo back as the `X-CSRF-Token` header on `DELETE /consents/:id`.',
        tags: ['Consents'],
        response: { 200: listResponseSchema, 401: unauthorizedResponseSchema },
      },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.code(401);
        return reply.send({ consents: [] });
      }

      const csrfToken = await ensureApiCsrfToken(fastify, session);

      const rows = await fastify.repositories.oauthConsents.listActiveForUserWithClient(
        session.userId
      );

      const consents = rows.map((row) => ({
        id: row.id,
        clientId: row.clientClientId,
        clientName: row.clientName,
        scopes: row.scopes,
        grantedAt: row.grantedAt,
      }));

      return reply.send({ consents, csrfToken });
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/consents/:id',
    {
      schema: {
        description:
          'Revoke an OAuth consent row owned by the currently signed-in user. Requires a valid `X-CSRF-Token` header whose value matches the session CSRF token returned by `GET /consents`.',
        tags: ['Consents'],
        params: z.object({ id: z.string().uuid() }),
        response: { 204: z.null(), 401: z.null() },
      },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.code(401);
        return reply.send(null);
      }

      // CSRF defence-in-depth (F-02): the caller MUST echo the per-session
      // CSRF token via the `X-CSRF-Token` header. The custom header forces a
      // CORS preflight for cross-origin attempts; the timing-safe comparison
      // closes the same-origin XSS gap that SameSite=Lax does not address.
      const provided = request.headers[CSRF_HEADER] as string | undefined;
      if (!csrfTokensEqual(provided, session.apiCsrfToken)) {
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: null,
          event: 'consents.revoke.csrf_failure',
          eventType: 'security',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { reason: 'missing_or_mismatched_csrf_token' },
        });
        throw new BadRequestError('invalid_csrf_token');
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
