import { randomUUID } from 'node:crypto';

import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { html, render } from '../../helpers/html';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { setSessionCookie } from '../../helpers/session-cookie';
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

function loginPage(opts: { returnTo: string; error?: string; email?: string }): string {
  const { returnTo, error, email } = opts;
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Sign in — QAuth</title>
          <style>
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
});

type LoginForm = z.infer<typeof loginFormSchema>;

export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/ui/login',
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
      reply.header('Content-Type', 'text/html; charset=utf-8');
      reply.header('Cache-Control', 'no-store');
      return reply.send(loginPage({ returnTo, error: q.error }));
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/ui/login',
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
      const normalizedEmail = normalizeEmail(body.email);

      const realm = await getOrCreateDefaultRealm(fastify);
      const user = await fastify.repositories.users.findByEmail(realm.id, normalizedEmail);

      let passwordValid = false;
      if (user) {
        passwordValid = await fastify.passwordHasher.verifyPassword(
          user.passwordHash,
          body.password
        );
      }

      if (!user || !passwordValid || !user.enabled) {
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
          email: user.email,
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
      reply.header('Cache-Control', 'no-store');
      return reply.redirect(returnTo, 302);
    }
  );
}
