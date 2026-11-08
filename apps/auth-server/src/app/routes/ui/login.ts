import {
  type PasswordAttempt,
  SignInStoreUnavailableError,
  type UpstreamProviderEntry,
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
import {
  normalizeInternalAuthorizeUrl,
  RESUME_PATH_PREFIX,
} from '../../helpers/pending-authorization';
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
import { uiStylesheetLink } from '../../helpers/ui-assets';
import { upstreamProviderCatalog } from '../../helpers/upstream-providers';
import { emitUserEvent } from '../../helpers/user-events';
import { walletLoginOfferedIn } from '../../helpers/wallet-login-request';
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
  /** Per-request CSP nonce (issue #113) stamped onto the page's own inline <style>. */
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
  /**
   * The realm's upstream providers the page offers (#639): a link each, to
   * the request the page was opened for, routed to the provider. Empty when
   * the page is for no authorization request, or the realm lists none.
   */
  upstreamProviders: readonly UpstreamProviderEntry[];
}): string {
  const { returnTo, cspNonce, csrfToken, error, email, walletLoginOffered, upstreamProviders } =
    opts;
  const walletLoginHref = `/ui/wallet-login?return_to=${encodeURIComponent(returnTo)}`;
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Sign in — QAuth</title>
          ${uiStylesheetLink()}
          <style nonce="${cspNonce}">
            .card {
              max-width: 23.75rem;
            }
            h1 {
              margin-bottom: 1.5rem;
            }
            .divider {
              display: flex;
              align-items: center;
              gap: 0.75rem;
              margin: 1.5rem 0 1rem;
              font-size: var(--text-xs);
              color: var(--muted-foreground);
            }
            .divider::before,
            .divider::after {
              content: '';
              flex: 1;
              border-top: 1px solid var(--border);
            }
            .providers {
              list-style: none;
              margin: 0;
              padding: 0;
            }
            .providers li + li,
            .providers + .alt-action {
              margin-top: 0.5rem;
            }
            .providers .alt-action,
            .divider + .alt-action {
              margin-top: 0;
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
              walletLoginOffered || upstreamProviders.length > 0
                ? html`<div class="divider"><span>or</span></div>`
                : ''
            }
            ${
              upstreamProviders.length > 0
                ? html`<ul class="providers" aria-label="Sign in with another provider">
                    ${upstreamProviders.map(
                      (provider) =>
                        html`<li>
                          <a
                            class="alt-action"
                            href="/ui/upstream/${encodeURIComponent(
                              provider.provider
                            )}?return_to=${encodeURIComponent(returnTo)}"
                            >Sign in with ${provider.name}</a
                          >
                        </li>`
                    )}
                  </ul>`
                : ''
            }
            ${
              walletLoginOffered
                ? html`<a class="alt-action" href="${walletLoginHref}">Sign in with your wallet</a>`
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
  const upstreamCatalog = upstreamProviderCatalog(fastify);
  /**
   * The upstream providers the page offers (#639): the realm's listed ones,
   * when the page is for an authorization request (`return_to` a parked
   * request or an authorize URL), which the provider's link starts again.
   */
  const upstreamProvidersFor = async (
    realmId: string,
    returnTo: string
  ): Promise<readonly UpstreamProviderEntry[]> =>
    returnTo.startsWith(RESUME_PATH_PREFIX) || normalizeInternalAuthorizeUrl(returnTo) !== null
      ? upstreamCatalog.offered(realmId)
      : [];
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
          walletLoginOffered: await walletLoginOfferedIn(fastify, requestRealm(request)),
          upstreamProviders: await upstreamProvidersFor(requestRealm(request).id, returnTo),
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
            walletLoginOffered: await walletLoginOfferedIn(fastify, requestRealm(request)),
            upstreamProviders: await upstreamProvidersFor(requestRealm(request).id, returnTo),
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

      const renderRefusal = async (statusCode: number, error: string) => {
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
            walletLoginOffered: await walletLoginOfferedIn(fastify, requestRealm(request)),
            upstreamProviders: await upstreamProvidersFor(requestRealm(request).id, returnTo),
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
            reason: unverified ? 'account_not_verified' : 'invalid_credentials',
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
        // RFC 8176 §2 (#662): the password is the one method this page
        // proves, and every code minted under the session says so.
        amr: ['pwd'],
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
