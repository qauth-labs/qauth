import type { BrowserSession } from '@qauth-labs/fastify-plugin-sessions';
import { InvalidCsrfTokenError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { resolveBrowserSession } from '../../helpers/browser-session';
import { listConsentsForUser, revokeConsentForUser } from '../../helpers/consent-management';
import { csrfTokensEqual, generateCsrfToken } from '../../helpers/session-cookie';
import { readSessionSideRecord, writeSessionSideRecord } from '../../helpers/session-side-record';
import { SignInRequiredError } from '../../helpers/sign-in-required';
import { emitUserEvent } from '../../helpers/user-events';

/**
 * Consent management JSON API (issue #150).
 *
 * Both endpoints require a valid `__Host-qauth_session` cookie; there is
 * no Bearer-token path here because consent is inherently a user-centric
 * operation. The developer portal, which holds an access token and no session
 * cookie, uses the Bearer-authenticated `/api/consents` instead (#366).
 *
 * Errors are problem documents, as on every route that is not an OAuth
 * protocol endpoint (ADR-019 Decision 7, #513). A request without a valid
 * session is a 401 `unauthorized` ({@link SignInRequiredError}), with no
 * `WWW-Authenticate` challenge: the credential is a cookie, not a token.
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

/** What a request without a valid browser session is told. */
const SIGN_IN_TO_MANAGE_CONSENTS = 'Sign in to manage your consents.';

/** Header name carrying the CSRF token on state-changing JSON requests. */
const CSRF_HEADER = 'x-csrf-token';

/**
 * Ensure the session's side record carries an `apiCsrfToken`; mint + persist
 * one if absent. The token is long-lived (per session) so concurrent /
 * multi-tab usage works. Returns the token to embed in a response.
 */
async function ensureApiCsrfToken(
  fastify: FastifyInstance,
  session: BrowserSession
): Promise<string> {
  const { apiCsrfToken } = await readSessionSideRecord(fastify, session);
  if (apiCsrfToken) return apiCsrfToken;
  const token = generateCsrfToken();
  // The side record expires with the session, never extending it.
  await writeSessionSideRecord(fastify, session, { apiCsrfToken: token });
  return token;
}

export default async function (fastify: FastifyInstance) {
  // Paths are relative to this module's directory. The route manifest
  // (`route-manifest.ts`) registers it under its directory's name, so the
  // `consents/` directory already contributes the `/consents` prefix — the same way
  // `routes/oauth/authorize.ts` declares `/authorize` and is served at
  // `/oauth/authorize`. Declaring `/consents` here would publish
  // `/consents/consents`.
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/',
    {
      schema: {
        description:
          'List the active OAuth consents for the currently signed-in user. Drives the developer portal revocation screen (issue #150). The response also carries a per-session CSRF token that the caller MUST echo back as the `X-CSRF-Token` header on `DELETE /consents/:id`.',
        tags: ['Consents'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [401],
        response: { 200: listResponseSchema },
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) throw new SignInRequiredError(SIGN_IN_TO_MANAGE_CONSENTS);

      const csrfToken = await ensureApiCsrfToken(fastify, session);
      const consents = await listConsentsForUser(fastify, session.userId);
      return reply.send({ consents, csrfToken });
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().delete(
    '/:id',
    {
      schema: {
        description:
          'Revoke an OAuth consent row owned by the currently signed-in user. Requires a valid `X-CSRF-Token` header whose value matches the session CSRF token returned by `GET /consents`.',
        tags: ['Consents'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400, 401, 404],
        params: z.object({ id: z.string().uuid() }),
        response: { 204: z.null() },
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) throw new SignInRequiredError(SIGN_IN_TO_MANAGE_CONSENTS);

      // CSRF defence-in-depth (F-02): the caller MUST echo the per-session
      // CSRF token via the `X-CSRF-Token` header. The custom header forces a
      // CORS preflight for cross-origin attempts; the timing-safe comparison
      // closes the same-origin XSS gap that SameSite=Lax does not address.
      const provided = request.headers[CSRF_HEADER] as string | undefined;
      const { apiCsrfToken } = await readSessionSideRecord(fastify, session);
      if (!csrfTokensEqual(provided, apiCsrfToken)) {
        await emitUserEvent(
          request,
          'urn:qauth:event:request.csrf_rejected:v1-rc.0',
          { form: 'consent_revocation' },
          { userId: session.userId, actor: 'user' }
        );
        throw new InvalidCsrfTokenError();
      }

      const { id } = request.params as { id: string };

      // Ownership check + event live in `helpers/consent-management` so this
      // surface and the Bearer-authenticated `/api/consents` cannot drift on
      // the security boundary (#366).
      await revokeConsentForUser(fastify, request, session.userId, id);

      reply.code(204);
      return reply.send(null);
    }
  );
}
