import { randomUUID } from 'node:crypto';

import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { verifyPasswordCredential } from '../../helpers/credential-auth';
import { html, render } from '../../helpers/html';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import {
  clearLoginCsrfCookie,
  csrfTokensEqual,
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  setLoginCsrfCookie,
  setSessionCookie,
  verifyLoginCsrfCookie,
} from '../../helpers/session-cookie';
import { ensureMinimumResponseTime } from '../../helpers/timing';

/**
 * Server-rendered login page (issue #150).
 *
 * Mounted under `/ui/*` to keep a hard boundary from the JSON APIs under
 * `/auth/*`: this handler sets a signed session cookie and redirects,
 * whereas `/auth/login` returns access + refresh tokens as JSON. The two
 * entry points share the same underlying password verification.
 *
 * The `return_to` query string is validated to be a relative path on our
 * own origin so we cannot be abused as an open redirector. Any failing
 * input falls back to `/`.
 */

function isSafeReturnTo(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  if (value.length === 0) return false;
  // Disallow absolute URLs, protocol-relative, or anything that doesn't
  // start with a single `/`. This keeps us off the open-redirector list.
  if (!value.startsWith('/')) return false;
  if (value.startsWith('//')) return false;
  return true;
}

function loginPage(opts: {
  returnTo: string;
  /** Per-request CSP nonce (issue #113) stamped onto the inline <style> tag. */
  cspNonce: string;
  /** Signed double-submit CSRF token; mirrored in the __Host- login cookie. */
  csrfToken: string;
  error?: string;
  email?: string;
}): string {
  const { returnTo, cspNonce, csrfToken, error, email } = opts;
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Sign in — QAuth</title>
          <style nonce="${cspNonce}">
            body {
              font-family:
                system-ui,
                -apple-system,
                Segoe UI,
                Roboto,
                sans-serif;
              background: #f6f7f9;
              color: #1a1a1a;
              margin: 0;
              min-height: 100vh;
              display: flex;
              align-items: center;
              justify-content: center;
            }
            .card {
              background: #fff;
              padding: 32px;
              border-radius: 12px;
              box-shadow: 0 4px 24px rgba(0, 0, 0, 0.06);
              width: 100%;
              max-width: 380px;
            }
            h1 {
              margin: 0 0 24px;
              font-size: 20px;
            }
            label {
              display: block;
              margin-top: 16px;
              font-size: 13px;
              font-weight: 600;
            }
            input[type='email'],
            input[type='password'] {
              display: block;
              width: 100%;
              padding: 10px 12px;
              margin-top: 6px;
              border: 1px solid #d8dbe0;
              border-radius: 6px;
              font-size: 14px;
              box-sizing: border-box;
            }
            button {
              margin-top: 24px;
              width: 100%;
              padding: 10px;
              border: 0;
              border-radius: 6px;
              background: #2a5bd7;
              color: #fff;
              font-weight: 600;
              font-size: 14px;
              cursor: pointer;
            }
            .error {
              background: #fdecea;
              color: #a1261b;
              padding: 10px 12px;
              border-radius: 6px;
              font-size: 13px;
              margin-bottom: 16px;
            }
          </style>
        </head>
        <body>
          <form class="card" method="post" action="/ui/login">
            <h1>Sign in to QAuth</h1>
            ${error ? html`<div class="error">${error}</div>` : ''}
            <input type="hidden" name="return_to" value="${returnTo}" />
            <input type="hidden" name="csrf_token" value="${csrfToken}" />
            <label>
              Email
              <input
                type="email"
                name="email"
                autocomplete="username"
                required
                value="${email ?? ''}"
              />
            </label>
            <label>
              Password
              <input type="password" name="password" autocomplete="current-password" required />
            </label>
            <button type="submit">Sign in</button>
          </form>
        </body>
      </html>`
  );
}

const loginFormSchema = z.object({
  email: z.string().min(1),
  password: z.string().min(1),
  return_to: z.string().optional(),
  // Signed double-submit CSRF token (login CSRF defence). Compared against the
  // value carried in the __Host- login-CSRF cookie.
  csrf_token: z.string().min(1),
});

type LoginForm = z.infer<typeof loginFormSchema>;

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/login',
    {
      schema: {
        description:
          'Renders the session-cookie login page. `return_to` is a relative path to redirect to after a successful sign-in. Issue #150.',
        tags: ['UI'],
        querystring: z.object({
          return_to: z.string().optional(),
          error: z.string().optional(),
        }),
      },
    },
    async (request, reply) => {
      const q = request.query as { return_to?: string; error?: string };
      const returnTo = isSafeReturnTo(q.return_to) ? q.return_to : '/';

      // Login CSRF defence (signed double-submit). Reuse an already-valid CSRF
      // cookie if the browser sent one (keeps a refreshed/multi-tab login page
      // consistent with its cookie); otherwise mint a fresh token and set it.
      const existing = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      const csrfToken = existing ?? generateCsrfToken();
      if (!existing) {
        setLoginCsrfCookie(reply, csrfToken);
      }

      reply.header('Content-Type', 'text/html; charset=utf-8');
      reply.header('Cache-Control', 'no-store');
      return reply.send(
        loginPage({ returnTo, cspNonce: reply.cspNonce.style, csrfToken, error: q.error })
      );
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/login',
    {
      schema: {
        description: 'Submit the session-cookie login form. Sets __Host-qauth_session on success.',
        tags: ['UI'],
        body: loginFormSchema,
      },
      config: {
        rateLimit: {
          max: env.LOGIN_RATE_LIMIT,
          timeWindow: env.LOGIN_RATE_WINDOW * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const startTime = Date.now();
      const body = request.body as LoginForm;
      const returnTo = isSafeReturnTo(body.return_to) ? body.return_to : '/';

      // Login CSRF defence (signed double-submit). Verify the __Host- cookie's
      // signature, then timing-compare its token against the submitted field.
      // A forged cross-site POST cannot present a matching pair because the
      // attacker can neither read the victim's cookie nor sign one. Checked
      // BEFORE any credential work so a CSRF probe never reaches the DB.
      const cookieCsrf = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      if (!cookieCsrf || !csrfTokensEqual(cookieCsrf, body.csrf_token)) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'ui.login.csrf_failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {},
        });
        // Re-render with a fresh token so the user can retry legitimately.
        const freshCsrf = generateCsrfToken();
        setLoginCsrfCookie(reply, freshCsrf);
        reply.header('Content-Type', 'text/html; charset=utf-8');
        reply.header('Cache-Control', 'no-store');
        reply.code(403);
        return reply.send(
          loginPage({
            returnTo,
            cspNonce: reply.cspNonce.style,
            csrfToken: freshCsrf,
            error: 'Your session expired. Please try again.',
            email: body.email,
          })
        );
      }

      const normalizedEmail = normalizeEmail(body.email);

      const realm = await getOrCreateDefaultRealm(fastify);

      // Password check via the user_credentials read path (#228); the enabled
      // gate below still reads the users row, which is fetched for the
      // session payload anyway.
      const check = await verifyPasswordCredential(fastify, {
        realmId: realm.id,
        email: normalizedEmail,
        password: body.password,
      });
      const user =
        check.status === 'ok'
          ? await fastify.repositories.users.findById(check.credential.userId)
          : undefined;
      if (check.status === 'ok' && !user) {
        // FK-impossible in normal operation — same operator-alerting log line
        // as the API login; the wire stays the generic 401 render below.
        fastify.log.error(
          { credentialId: check.credential.id },
          'password credential without a users row'
        );
      }

      if (check.status !== 'ok' || !user || !user.enabled) {
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'ui.login.failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { email: normalizedEmail },
        });
        reply.header('Content-Type', 'text/html; charset=utf-8');
        reply.header('Cache-Control', 'no-store');
        reply.code(401);
        return reply.send(
          loginPage({
            returnTo,
            cspNonce: reply.cspNonce.style,
            // The CSRF cookie is still valid on a credential failure — reuse it
            // so the re-rendered form keeps matching the cookie.
            csrfToken: cookieCsrf,
            error: 'Invalid email or password.',
            email: body.email,
          })
        );
      }

      // Session-fixation defense: always mint a fresh session id on a
      // successful credential check, even if the browser already had one.
      const sessionId = randomUUID();
      await fastify.sessionUtils.setSession(
        sessionId,
        {
          userId: user.id,
          // #230: the credential's external_sub is the authenticated address.
          email: check.credential.externalSub,
          sessionId,
          createdAt: Date.now(),
        },
        env.SESSION_COOKIE_TTL
      );

      await fastify.repositories.users.updateLastLogin(user.id);
      await fastify.repositories.auditLogs.create({
        userId: user.id,
        oauthClientId: null,
        event: 'ui.login.success',
        eventType: 'auth',
        success: true,
        ipAddress: request.ip,
        userAgent: request.headers['user-agent'] || null,
        metadata: { sessionId, returnTo },
      });

      setSessionCookie(reply, sessionId);
      // Burn the login-CSRF cookie now that authentication succeeded. Fastify
      // accumulates multiple Set-Cookie headers into an array, so this does not
      // clobber the session cookie set just above.
      clearLoginCsrfCookie(reply);
      reply.header('Cache-Control', 'no-store');
      return reply.redirect(returnTo, 302);
    }
  );
}
