import {
  type PasswordAttempt,
  SignInStoreUnavailableError,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import { MIN_RESPONSE_TIME_MS } from '../../constants';
import { accountPoliciesOf } from '../../helpers/account-policies';
import { hashEmail } from '../../helpers/auth-events';
import { createBrowserSession } from '../../helpers/browser-session';
import { clientAddressKey } from '../../helpers/client-address';
import { verifyPasswordCredential } from '../../helpers/credential-auth';
import { recordSuccessfulLogin, registerLoginAttempt } from '../../helpers/failed-login';
import { html, render } from '../../helpers/html';
import { ladderEndUserIp } from '../../helpers/password-attempts';
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
import { isSafeReturnTo } from '../../helpers/return-to';
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
import { emitUserEvent } from '../../helpers/user-events';
import { resolveWalletLoginCapability } from '../../helpers/wallet-login-request';
import { type LoginForm, loginFormSchema } from '../../schemas/auth';

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

/** The `Retry-After` of a sign-in refused because the failure ladder's store failed (#615). */
const LADDER_UNAVAILABLE_RETRY_SECONDS = 5;

/** The sign-in page's HTML: the form, an optional refusal and the wallet link. */
function loginPage(opts: {
  returnTo: string;
  /** Per-request CSP nonce (issue #113) stamped onto the inline <style> tag. */
  cspNonce: string;
  /** Signed double-submit CSRF token; mirrored in the __Host- login cookie. */
  csrfToken: string;
  error?: string;
  email?: string;
  /**
   * Whether to offer the wallet-login entry point (#239). FAIL-CLOSED: the link
   * is rendered only when the deployment can actually serve the flow — wallet
   * federation on, a `VerifierProfile` selected and operable, a credential type
   * configured. With none of that, the page presents no wallet flow at all
   * rather than a link that refuses (#296, LOCKED).
   */
  walletLoginOffered: boolean;
}): string {
  const { returnTo, cspNonce, csrfToken, error, email, walletLoginOffered } = opts;
  const walletLoginHref = `/ui/wallet-login?return_to=${encodeURIComponent(returnTo)}`;
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
            .divider {
              margin: 24px 0 16px;
              border-top: 1px solid #e5e7eb;
              text-align: center;
              font-size: 12px;
              color: #6b7280;
            }
            .divider span {
              position: relative;
              top: -9px;
              background: #fff;
              padding: 0 8px;
            }
            .alt-action {
              display: block;
              width: 100%;
              padding: 10px;
              border: 1px solid #2a5bd7;
              border-radius: 6px;
              background: #fff;
              color: #2a5bd7;
              font-weight: 600;
              font-size: 14px;
              text-align: center;
              text-decoration: none;
              box-sizing: border-box;
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
            ${
              walletLoginOffered
                ? html`<div class="divider"><span>or</span></div>
                    <a class="alt-action" href="${walletLoginHref}">Sign in with your wallet</a>`
                : ''
            }
          </form>
        </body>
      </html>`
  );
}

/**
 * The one refusal text for a sign-in that did not succeed: unknown address,
 * wrong password, disabled account and, under the verified-account gate, an
 * unverified one. The text cannot say which. While the realm's gate is on
 * (#528) it names the unverified case among the possibilities, so a person who
 * has just registered knows to open the verification mail first.
 */
function signInRefusal(requireVerifiedAccount: boolean): string {
  return requireVerifiedAccount
    ? 'Invalid email or password. If you have just registered, confirm your email address first with the link we sent you.'
    : 'Invalid email or password.';
}

/**
 * Register the session-cookie sign-in routes under `/ui`: `GET /login`, which
 * renders the page with a CSRF value mirrored in a signed cookie, and
 * `POST /login`, which checks the form and, on success, creates a browser
 * session and redirects to `return_to`.
 */
export default async function (fastify: FastifyInstance) {
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/login',
    {
      schema: {
        description:
          'Renders the session-cookie login page. `return_to` is a relative path to redirect to after a successful sign-in. Issue #150.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        // No `error` parameter: the page never shows caller-supplied text.
        // The server's own refusals are fixed strings rendered by the POST.
        querystring: z.object({
          return_to: z.string().optional(),
        }),
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const q = request.query as { return_to?: string };
      const returnTo = isSafeReturnTo(q.return_to) ? q.return_to : '/';

      // Login CSRF defence (signed double-submit). Reuse an already-valid CSRF
      // cookie if the browser sent one (keeps a refreshed/multi-tab login page
      // consistent with its cookie); otherwise mint a fresh token and set it.
      const existing = await verifyLoginCsrfCookie(
        fastify,
        requestRealm(request).id,
        readCookie(request, LOGIN_CSRF_COOKIE_NAME)
      );
      const csrfToken = existing ?? generateCsrfToken();
      if (!existing) {
        await setLoginCsrfCookie(fastify, reply, requestRealm(request).id, csrfToken);
      }

      reply.header('Content-Type', 'text/html; charset=utf-8');
      reply.header('Cache-Control', 'no-store');
      return reply.send(
        loginPage({
          returnTo,
          cspNonce: reply.cspNonce.style,
          csrfToken,
          walletLoginOffered: resolveWalletLoginCapability(fastify) !== undefined,
        })
      );
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/login',
    {
      schema: {
        description: 'Submit the session-cookie login form. Sets __Host-qauth_session on success.',
        tags: ['UI'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [400],
        body: loginFormSchema,
      },
      config: {
        surface: 'browser',
        rateLimit: {
          max: env.LOGIN_RATE_LIMIT,
          timeWindow: env.LOGIN_RATE_WINDOW * 1000,
          keyGenerator: realmRateLimitKey,
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
      const cookieCsrf = await verifyLoginCsrfCookie(
        fastify,
        requestRealm(request).id,
        readCookie(request, LOGIN_CSRF_COOKIE_NAME)
      );
      if (!cookieCsrf || !csrfTokensEqual(cookieCsrf, body.csrf_token)) {
        await emitUserEvent(
          request,
          'urn:qauth:event:request.csrf_rejected:v1-rc.0',
          { form: 'sign_in' },
          { actor: 'user' }
        );
        // Re-render with a fresh token so the user can retry legitimately.
        const freshCsrf = generateCsrfToken();
        await setLoginCsrfCookie(fastify, reply, requestRealm(request).id, freshCsrf);
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
            walletLoginOffered: resolveWalletLoginCapability(fastify) !== undefined,
          })
        );
      }

      const normalizedEmail = normalizeEmail(body.email);
      // Failed-login throttling (#115), with the SAME identifiers as
      // POST /auth/login so both front doors share one counter: guesses spread
      // across them add up, and an account locked on one is locked on both.
      // Counted in the realm of the host the request named (#487), the realm
      // the account is looked up in.
      const realm = requestRealm(request);
      const emailIdentifier = `email:${hashEmail(normalizedEmail)}`;
      const lockoutIdentifiers = [emailIdentifier, `ip:${clientAddressKey(request)}`];
      // The realm's verified-account gate and brute-force policy (#528), from
      // the resolver's row: no query.
      const policies = accountPoliciesOf(fastify, realm);

      const renderRefusal = (statusCode: number, error: string) => {
        reply.header('Content-Type', 'text/html; charset=utf-8');
        reply.header('Cache-Control', 'no-store');
        reply.code(statusCode);
        return reply.send(
          loginPage({
            returnTo,
            cspNonce: reply.cspNonce.style,
            // The CSRF cookie is still valid on a refusal — reuse it so the
            // re-rendered form keeps matching the cookie.
            csrfToken: cookieCsrf,
            error,
            email: body.email,
            walletLoginOffered: resolveWalletLoginCapability(fastify) !== undefined,
          })
        );
      };

      // Refuse a locked-out identifier, else count the attempt before the
      // password is looked at (#115), exactly as POST /auth/login does.
      const lockout = await registerLoginAttempt(
        fastify.redis,
        realm.id,
        policies.bruteForce,
        lockoutIdentifiers
      );
      if (lockout.locked) {
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
        // No subject, and never the typed address: the attempt names no user.
        await emitUserEvent(
          request,
          'urn:qauth:event:user.sign_in_failed:v1-rc.0',
          { method: 'password', reason: 'locked_out' },
          { realmId: realm.id, actor: 'user' }
        );
        if (lockout.retryAfterSeconds !== undefined) {
          reply.header('Retry-After', String(lockout.retryAfterSeconds));
        }
        return renderRefusal(429, 'Too many failed sign-in attempts. Please try again later.');
      }

      // The per-account failure ladder (#615), beside the lock above and
      // shared with POST /auth/login and the sign-in engine: the attempt is
      // reserved before the password is read. One inside the account's wait
      // is refused like a locked one, neither verified nor counted; a store
      // that fails refuses the attempt before any credential is checked.
      let attempt: PasswordAttempt;
      try {
        attempt = await fastify.passwordAttempts.reserve({
          realmId: realm.id,
          identifier: normalizedEmail,
          ...ladderEndUserIp(request),
        });
      } catch (error) {
        if (!(error instanceof SignInStoreUnavailableError)) throw error;
        fastify.log.error({ err: error, port: error.port }, 'sign-in failure ladder unavailable');
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
        await emitUserEvent(
          request,
          'urn:qauth:event:user.sign_in_failed:v1-rc.0',
          { method: 'password', reason: 'internal_error' },
          { realmId: realm.id, actor: 'user' }
        );
        reply.header('Retry-After', String(LADDER_UNAVAILABLE_RETRY_SECONDS));
        return renderRefusal(503, 'Sign-in is unavailable right now. Please try again shortly.');
      }
      if (attempt.kind === 'wait') {
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
        await emitUserEvent(
          request,
          'urn:qauth:event:user.sign_in_failed:v1-rc.0',
          { method: 'password', reason: 'locked_out' },
          { realmId: realm.id, actor: 'user' }
        );
        reply.header('Retry-After', String(attempt.retryAfterSeconds));
        return renderRefusal(429, 'Too many failed sign-in attempts. Please try again later.');
      }

      // Password check via the user_credentials read path (#228); the enabled
      // gate below still reads the users row.
      const check = await verifyPasswordCredential(fastify, {
        realmId: realm.id,
        email: normalizedEmail,
        password: body.password,
      });

      // Verified-account gate (F-08), identical to POST /auth/login: with the
      // realm's `accounts.requireVerifiedAccount` on (the default; #528) an
      // unverified credential gets no session, so it cannot complete an
      // OAuth/OIDC flow through the hosted UI either. It is refused EXACTLY
      // like a wrong password (same 401 page, same floor, same order of work,
      // still counted): a page of its own told a just-registered free address
      // from a registered one (ANT-2026-SPEMY9GU). Only the event keeps the
      // reason.
      const unverified =
        check.status === 'ok' && !check.accountVerified && policies.requireVerifiedAccount;

      // The session's issue time, taken before the account is read (#748): a
      // disablement that commits after the read is not seen by it.
      const issuedAt = Date.now();
      const user =
        check.status === 'ok' && !unverified
          ? await fastify.repositories.users.findById(realm.id, check.credential.userId)
          : undefined;
      if (check.status === 'ok' && !unverified && !user) {
        // FK-impossible in normal operation — same operator-alerting log line
        // as the API login; the wire stays the generic 401 render below.
        fastify.log.error(
          { credentialId: check.credential.id },
          'password credential without a users row'
        );
      }

      if (check.status !== 'ok' || unverified || !user || !user.enabled) {
        // The attempt stays counted on the ladder; at its hard ceiling the
        // hard action (#615) may disable the usable password of an enabled
        // account, read only then. A disabled user is never changed.
        const refusedUserId =
          check.status === 'ok'
            ? check.credential.userId
            : check.status === 'invalid'
              ? check.userId
              : undefined;
        await attempt.failed(async () => {
          if (refusedUserId === undefined) return null;
          const owner =
            user ?? (await fastify.repositories.users.findById(realm.id, refusedUserId));
          return owner?.enabled === true ? { userId: owner.id } : null;
        });
        await ensureMinimumResponseTime(startTime, MIN_RESPONSE_TIME_MS.LOGIN);
        // The unverified account is a known user, and the event's subject.
        await emitUserEvent(
          request,
          'urn:qauth:event:user.sign_in_failed:v1-rc.0',
          {
            method: 'password',
            reason: unverified ? 'email_not_verified' : 'invalid_credentials',
          },
          {
            realmId: realm.id,
            userId: unverified ? check.credential.userId : null,
            actor: 'user',
          }
        );
        return renderRefusal(401, signInRefusal(policies.requireVerifiedAccount));
      }

      // As on POST /auth/login: the account's state is cleared; the source
      // address only gets back this attempt's own count, not the failures
      // other attempts left on it.
      await recordSuccessfulLogin(fastify.redis, realm.id, policies.bruteForce, lockout, [
        emailIdentifier,
      ]);
      // The ladder: the password's counter is cleared, this address becomes
      // known to the account, and a mark the unarmed hard action ignored is
      // cleared (#615).
      await attempt.succeeded({ userId: user.id, ignoredMark: check.ignoredMark });

      // Session-fixation defense: always a new session, with a new `sid`, on
      // a successful credential check, even if the browser already had one.
      // The session service stores it in Postgres (#488).
      const session = await createBrowserSession(fastify, request, {
        realmId: realm.id,
        userId: user.id,
        // #230: the credential's external_sub is the authenticated address.
        identifier: check.credential.externalSub,
        issuedAt,
      });

      await fastify.repositories.users.updateLastLogin(realm.id, user.id);
      await emitUserEvent(
        request,
        'urn:qauth:event:user.signed_in:v1-rc.0',
        { method: 'password' },
        { realmId: realm.id, userId: user.id, actor: 'user' }
      );

      await setSessionCookie(fastify, reply, session);
      // Burn the login-CSRF cookie now that authentication succeeded. Fastify
      // accumulates multiple Set-Cookie headers into an array, so this does not
      // clobber the session cookie set just above.
      clearLoginCsrfCookie(reply);
      reply.header('Cache-Control', 'no-store');
      return reply.redirect(returnTo, 302);
    }
  );
}
