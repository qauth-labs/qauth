import { randomUUID } from 'node:crypto';

import { DIRECT_POST_RESPONSE_MODE } from '@qauth-labs/fastify-plugin-federation';
import { normalizeEmail } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  ASSERTED_IDENTIFIER_MAX_LENGTH,
  WALLET_LOGIN_POLL_INTERVAL_MS,
  WALLET_LOGIN_STATUS_RATE_LIMIT,
  WALLET_LOGIN_STATUS_RATE_WINDOW_S,
} from '../../constants';
import { html, render, safe, safeCustomSchemeUrl, type SafeHtml } from '../../helpers/html';
import { encodeQrCode, renderQrCodeSvg } from '../../helpers/qr-code';
import { getOrCreateDefaultRealm } from '../../helpers/realm';
import { resolveReturnTo } from '../../helpers/return-to';
import {
  clearLoginCsrfCookie,
  csrfTokensEqual,
  dropWalletFlowBinding,
  findWalletFlowBinder,
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  readWalletFlowBindings,
  setLoginCsrfCookie,
  setSessionCookie,
  setWalletFlowCookie,
  verifyLoginCsrfCookie,
  WALLET_FLOW_COOKIE_NAME,
} from '../../helpers/session-cookie';
import {
  createWalletLoginFlow,
  deleteWalletLoginFlow,
  deleteWalletPresentationSignal,
  generateWalletFlowSecret,
  isWalletLoginHandle,
  readWalletLoginFlow,
  readWalletPresentationSignal,
  type WalletLoginFlow,
} from '../../helpers/wallet-login-flow';
import {
  buildWalletLoginInvocation,
  resolveWalletLoginCapability,
} from '../../helpers/wallet-login-request';
import { resolveWalletPresentation } from '../../helpers/wallet-presentation';

/**
 * Server-rendered WALLET LOGIN screens (issue #239, ADR-004 / ADR-009).
 *
 * Mounted under `/ui/*` alongside the password login it extends, and built on
 * the same primitives: the same `html` escaping helper, the same signed
 * double-submit login-CSRF cookie, the same `__Host-` session cookie, the same
 * `return_to` guard. It is an additional way to arrive at a browser session, not
 * a parallel UI.
 *
 * ## The identifier field is not polish
 *
 * ADR-009 Decision §1: `asserted-lookup` is the universal default because **no
 * protocol-guaranteed stable wallet subject identifier exists**. The user
 * asserts which account they mean; the presentation proves entitlement to it.
 * There is therefore **no usernameless wallet login**, and the field is
 * REQUIRED. The ADR calls this out as counter-intuitive enough that a future
 * implementer will try to remove it — removing it does not simplify the flow, it
 * makes the flow unimplementable.
 *
 * Note what the field does NOT do: it is never looked up before the presentation
 * arrives. Submitting it always renders a QR code, whether or not an account
 * exists, so the screen is not an account oracle.
 *
 * ## Targeting surface — QR / deep link only (SCOPE DECISION, #239)
 *
 * OID4VP 1.0 offers two ways to reach a wallet: the cross-device QR / same-device
 * deep link handled here, and the browser-native Digital Credentials API, whose
 * `origin:` Client Identifier Prefix is reserved for it. **This issue ships
 * QR/deep-link only.** The DC API path requires that prefix, which
 * `client-identifier.ts` does not implement, and its request must be signed —
 * which needs #298. Shipping half of it would mean an entry point that works in
 * one browser build and fails everywhere else. The invocation URI is treated as
 * opaque throughout, so adding the DC API later changes what the backend
 * produces, not this screen's structure.
 *
 * ## Fail-closed, twice
 *
 * The routes are not REGISTERED unless `WALLET_FEDERATION_ENABLED` is on (a
 * default deployment answers 404 — the screens do not exist rather than existing
 * and refusing), and every handler re-resolves the capability per request, so a
 * deployment that ends up with no usable `VerifierProfile` refuses instead of
 * falling back to a permissive posture (#296, LOCKED).
 *
 * ## One refusal, always
 *
 * Expired request, wallet-reported error, unvalidatable presentation, untrusted
 * issuer, unknown account, disabled account: ALL render
 * {@link WALLET_LOGIN_REFUSAL}. #236's rule is that an untrusted issuer must not
 * be distinguishable from a malformed presentation, and on a login screen the
 * difference between "no such account" and "credential rejected" would be an
 * account oracle available to anyone. The reason is logged server-side; the
 * browser gets one sentence.
 */

/** The ONE sentence any wallet-login failure renders. */
export const WALLET_LOGIN_REFUSAL = 'We could not complete that sign-in. Please try again.';

/** Copy for a flow whose presentation request timed out. */
export const WALLET_LOGIN_EXPIRED = 'This sign-in request has expired. Please start again.';

/** Shared page chrome, so the three screens cannot drift apart visually. */
function pageStyles(cspNonce: string): SafeHtml {
  return html`<style nonce="${cspNonce}">
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
      max-width: 420px;
    }
    h1 {
      margin: 0 0 12px;
      font-size: 20px;
    }
    p {
      margin: 0 0 12px;
      font-size: 14px;
      line-height: 1.5;
      color: #374151;
    }
    label {
      display: block;
      margin-top: 16px;
      font-size: 13px;
      font-weight: 600;
    }
    input[type='text'] {
      display: block;
      width: 100%;
      padding: 10px 12px;
      margin-top: 6px;
      border: 1px solid #d8dbe0;
      border-radius: 6px;
      font-size: 14px;
      box-sizing: border-box;
    }
    .hint {
      margin-top: 6px;
      font-size: 12px;
      color: #6b7280;
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
    .status {
      background: #eef2ff;
      color: #27337a;
      padding: 10px 12px;
      border-radius: 6px;
      font-size: 13px;
      margin-top: 16px;
    }
    .qr {
      width: 240px;
      max-width: 100%;
      margin: 20px auto;
      border: 1px solid #e5e7eb;
      border-radius: 8px;
      padding: 8px;
      background: #fff;
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
      margin-top: 16px;
    }
    .footer-link {
      display: block;
      margin-top: 20px;
      font-size: 13px;
      text-align: center;
    }
  </style>`;
}

/** Screen 1 — assert an account, then start the presentation request. */
function identifierPage(opts: {
  returnTo: string;
  cspNonce: string;
  csrfToken: string;
  error?: string;
  identifier?: string;
}): string {
  const { returnTo, cspNonce, csrfToken, error, identifier } = opts;
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Sign in with your wallet — QAuth</title>
          ${pageStyles(cspNonce)}
        </head>
        <body>
          <form class="card" method="post" action="/ui/wallet-login">
            <h1>Sign in with your wallet</h1>
            ${error ? html`<div class="error" role="alert">${error}</div>` : ''}
            <p>
              Tell us which account you are signing in to, then present a credential from your
              wallet to prove it is yours.
            </p>
            <input type="hidden" name="return_to" value="${returnTo}" />
            <input type="hidden" name="csrf_token" value="${csrfToken}" />
            <label>
              Email or username
              <input
                type="text"
                name="identifier"
                autocomplete="username"
                autocapitalize="none"
                spellcheck="false"
                required
                maxlength="${ASSERTED_IDENTIFIER_MAX_LENGTH}"
                aria-describedby="identifier-hint"
                value="${identifier ?? ''}"
              />
            </label>
            <p class="hint" id="identifier-hint">
              Your wallet does not tell us who you are, so we need you to say which account you
              mean.
            </p>
            <button type="submit">Continue</button>
            <a class="footer-link" href="/ui/login?return_to=${encodeURIComponent(returnTo)}"
              >Sign in with a password instead</a
            >
          </form>
        </body>
      </html>`
  );
}

/**
 * Screen 2 — the wallet invocation, plus the wait.
 *
 * The deep link is a plain anchor rather than a script-driven navigation: the
 * invocation URI is a custom scheme or a universal link, and letting the browser
 * decide what to do with it is what makes both work. `safeUrl()` from `html.ts`
 * cannot guard it — that helper allowlists http/https/mailto, and this href is
 * `openid4vp://…` by design — so it goes through that file's denylist
 * counterpart, `safeCustomSchemeUrl()`, instead: any scheme a wallet might
 * register is fine, `javascript:`/`data:`/`vbscript:` and their encoded
 * spellings are not. HTML-escaping alone would not help here, because
 * `javascript:alert(1)` contains nothing `esc()` touches.
 *
 * `federationEnvSchema` already refuses to boot on such a value (#239), so this
 * branch is unreachable through configuration. That is deliberate: neither check
 * is load-bearing on its own, and the render path stays safe if a future caller
 * feeds this screen a URI from somewhere other than `OID4VP_WALLET_INVOCATION_
 * ENDPOINT`. When the link is refused the QR still renders — the page is
 * unusable either way, but it must not emit an executable href.
 *
 * The QR code degrades rather than throws: a payload past the encoder's maximum
 * (`QR_MAX_BYTES`) renders the deep-link button and an explanation, because an
 * over-long invocation URI is a configuration outcome and this screen must not
 * 500 on it.
 */
function pendingPage(opts: {
  handle: string;
  invocationUri: string;
  cspNonce: string;
  scriptNonce: string;
  returnTo: string;
}): string {
  const { handle, invocationUri, cspNonce, scriptNonce, returnTo } = opts;
  const qr = encodeQrCode(invocationUri);
  const deepLink = safeCustomSchemeUrl(invocationUri);
  const statusPath = `/ui/wallet-login/${handle}/status`;

  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Waiting for your wallet — QAuth</title>
          ${pageStyles(cspNonce)}
        </head>
        <body>
          <div class="card">
            <h1>Present a credential</h1>
            <p>Scan this code with your wallet, or open your wallet on this device.</p>
            ${
              qr === undefined
                ? html`<p class="hint">
                    This request is too large to show as a code. Use the button below on the device
                    your wallet is installed on.
                  </p>`
                : html`<div class="qr">
                    ${safe(renderQrCodeSvg(qr, 'QR code containing the wallet sign-in request'))}
                  </div>`
            }
            ${
              deepLink === undefined
                ? html`<p class="hint">
                    This deployment cannot offer an open-my-wallet link. Contact your administrator.
                  </p>`
                : html`<a class="alt-action" href="${deepLink}">Open my wallet</a>`
            }
            <div class="status" id="wallet-status" role="status" aria-live="polite">
              Waiting for your wallet…
            </div>
            <noscript>
              <p class="hint">
                This page updates itself when JavaScript is enabled.
                <a href="/ui/wallet-login/${handle}">Check whether your wallet has responded</a>.
              </p>
            </noscript>
            <a class="footer-link" href="/ui/login?return_to=${encodeURIComponent(returnTo)}"
              >Cancel and sign in with a password</a
            >
          </div>
          <script nonce="${scriptNonce}">
            (function () {
              var statusUrl = ${safe(JSON.stringify(statusPath))};
              var interval = ${WALLET_LOGIN_POLL_INTERVAL_MS};
              var region = document.getElementById('wallet-status');
              function poll() {
                fetch(statusUrl, {
                  credentials: 'same-origin',
                  headers: { Accept: 'application/json' },
                })
                  .then(function (response) {
                    return response.ok ? response.json() : null;
                  })
                  .then(function (body) {
                    if (!body || body.status === 'pending') {
                      window.setTimeout(poll, interval);
                      return;
                    }
                    if (body.status === 'complete' && body.redirect_to) {
                      window.location.assign(body.redirect_to);
                      return;
                    }
                    region.textContent = body.message || '';
                  })
                  .catch(function () {
                    window.setTimeout(poll, interval);
                  });
              }
              window.setTimeout(poll, interval);
            })();
          </script>
        </body>
      </html>`
  );
}

/** Screen 3 — a terminal state: expired, refused, or not available. */
function terminalPage(opts: {
  cspNonce: string;
  title: string;
  message: string;
  returnTo: string;
  retry: boolean;
}): string {
  const { cspNonce, title, message, returnTo, retry } = opts;
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${title} — QAuth</title>
          ${pageStyles(cspNonce)}
        </head>
        <body>
          <div class="card">
            <h1>${title}</h1>
            <p role="alert">${message}</p>
            ${
              retry
                ? html`<a
                    class="alt-action"
                    href="/ui/wallet-login?return_to=${encodeURIComponent(returnTo)}"
                    >Try again</a
                  >`
                : ''
            }
            <a class="footer-link" href="/ui/login?return_to=${encodeURIComponent(returnTo)}"
              >Sign in with a password</a
            >
          </div>
        </body>
      </html>`
  );
}

const walletLoginFormSchema = z.object({
  /**
   * The account the user ASSERTS (ADR-009 §1). Bounded like every other
   * pre-authentication string in this codebase — it reaches Redis and, later, an
   * `external_sub` lookup.
   */
  identifier: z.string().min(1).max(ASSERTED_IDENTIFIER_MAX_LENGTH),
  return_to: z.string().optional(),
  csrf_token: z.string().min(1),
});

type WalletLoginForm = z.infer<typeof walletLoginFormSchema>;

const walletLoginStatusSchema = z.object({
  status: z.enum(['pending', 'complete', 'expired', 'rejected']),
  /** Present on every terminal status except `complete`. Fixed server copy. */
  message: z.string().optional(),
  /** Present only on `complete`: the relative path to continue to. */
  redirect_to: z.string().optional(),
});

/**
 * Normalize the asserted identifier.
 *
 * ADR-009 §1 stores it in `user_credentials.external_sub`, the same column
 * `PasswordProvider` fills with a normalized email — so it must be normalized
 * the SAME way or the two providers would disagree about what "the same account"
 * means. Email and username normalize identically today (trim + lowercase);
 * this function is the single place that changes if they ever stop doing so.
 */
function normalizeAssertedIdentifier(value: string): string {
  return normalizeEmail(value);
}

/** How this flow ended, as far as the browser is concerned. */
type FlowOutcome =
  | { status: 'pending'; flow: WalletLoginFlow }
  | { status: 'complete'; redirectTo: string }
  | { status: 'expired' }
  | { status: 'rejected' };

/**
 * Read a flow, apply the browser binder, and advance it as far as it can go.
 *
 * The ONE place a wallet-login flow changes state, shared by the page handler
 * (which redirects or re-renders) and the status handler (which answers JSON).
 * Two surfaces observing the same flow through two implementations is how one of
 * them ends up skipping the binder check.
 *
 * Missing flow, wrong binder and expired flow all return `expired`: they are
 * indistinguishable to the caller by design, so a handle harvested from a screen
 * share or a log cannot be probed for whether it was ever real.
 */
async function advanceWalletLoginFlow(
  fastify: FastifyInstance,
  request: FastifyRequest,
  reply: FastifyReply,
  handle: string
): Promise<FlowOutcome> {
  const flow = await readWalletLoginFlow(fastify, handle);
  if (flow === null) return { status: 'expired' };

  // Browser binding. Without it, an attacker could start a flow, present their
  // own credential and hand the victim the URL — the victim's browser would
  // finish the flow and be signed in as the attacker. Looked up BY HANDLE, so a
  // second flow started in the same browser does not unbind this one. See
  // `WALLET_FLOW_COOKIE_NAME`.
  const binder = findWalletFlowBinder(readCookie(request, WALLET_FLOW_COOKIE_NAME), handle);
  if (!binder || !csrfTokensEqual(flow.binder, binder)) {
    fastify.log.warn(
      { ip: request.ip },
      'wallet-login flow accessed without its browser binder cookie'
    );
    return { status: 'expired' };
  }

  if (Date.now() >= flow.expiresAt) {
    await terminate(fastify, handle, flow);
    return { status: 'expired' };
  }

  const signal = await readWalletPresentationSignal(fastify, flow.stateHash);
  if (signal === null) return { status: 'pending', flow };

  if (signal === 'wallet_error') {
    await terminate(fastify, handle, flow);
    return { status: 'rejected' };
  }

  // A presentation arrived. Everything from here is the seam that turns it into
  // a session (#235). No `credential` is passed because the `direct_post` route
  // cannot produce a validated one yet — issuer key material is not
  // configurable — so the seam refuses on its first gate. See
  // `helpers/wallet-presentation.ts`.
  const resolution = await resolveWalletPresentation(fastify, {
    realmId: flow.realmId,
    stateHash: flow.stateHash,
    assertedIdentifier: flow.assertedIdentifier,
  });

  await terminate(fastify, handle, flow);

  if (resolution.status !== 'authenticated') {
    await auditWalletLogin(fastify, request, {
      userId: null,
      success: false,
      metadata: { assertedIdentifier: flow.assertedIdentifier, reason: 'not_resolved' },
    });
    return { status: 'rejected' };
  }

  // The `enabled` gate, exactly as the password login applies it: a valid
  // credential for a disabled account is still a refused sign-in, and it must
  // look like every other refusal.
  const user = await fastify.repositories.users.findById(resolution.userId);
  if (!user || !user.enabled) {
    fastify.log.warn(
      { userId: resolution.userId },
      'wallet presentation resolved to a missing or disabled user'
    );
    await auditWalletLogin(fastify, request, {
      userId: null,
      success: false,
      metadata: { assertedIdentifier: flow.assertedIdentifier, reason: 'user_unavailable' },
    });
    return { status: 'rejected' };
  }

  // Session-fixation defence: a fresh session id on every successful
  // authentication, even if the browser already had one.
  const sessionId = randomUUID();
  await fastify.sessionUtils.setSession(
    sessionId,
    {
      userId: user.id,
      // The value stored as this credential's `external_sub` — the asserted,
      // normalized identifier (ADR-009 §1), mirroring what the password login
      // puts here.
      email: resolution.externalSub,
      sessionId,
      createdAt: Date.now(),
      // #237: the eIDAS LoA the presented credential and its issuer established,
      // carried on the session so `/oauth/authorize` can bind it to the
      // authorization code and `/oauth/token` can assert `acr` in the ID token.
      // Spread conditionally so a resolution that established nothing leaves the
      // field ABSENT rather than storing `'low'` — the password login stores
      // nothing here either, and "no assurance" must have one representation.
      ...(resolution.assuranceLevel !== undefined && resolution.assuranceLevel !== 'low'
        ? { assuranceLevel: resolution.assuranceLevel }
        : {}),
    },
    env.SESSION_COOKIE_TTL
  );

  await fastify.repositories.users.updateLastLogin(user.id);
  await auditWalletLogin(fastify, request, {
    userId: user.id,
    success: true,
    metadata: { sessionId, returnTo: flow.returnTo, verifierProfile: flow.verifierProfile },
  });

  setSessionCookie(reply, sessionId);
  // Burn only THIS flow's binding: another flow may still be pending in the
  // same browser, and clearing the whole cookie would strand it.
  dropWalletFlowBinding(request, reply, handle);

  return { status: 'complete', redirectTo: flow.returnTo };
}

/** Drop every trace of a finished flow so nothing can be polled or replayed. */
async function terminate(
  fastify: FastifyInstance,
  handle: string,
  flow: WalletLoginFlow
): Promise<void> {
  await deleteWalletLoginFlow(fastify, handle);
  await deleteWalletPresentationSignal(fastify, flow.stateHash);
}

async function auditWalletLogin(
  fastify: FastifyInstance,
  request: FastifyRequest,
  entry: { userId: string | null; success: boolean; metadata: Record<string, unknown> }
): Promise<void> {
  await fastify.repositories.auditLogs.create({
    userId: entry.userId,
    oauthClientId: null,
    event: entry.success ? 'ui.wallet_login.success' : 'ui.wallet_login.failure',
    eventType: 'auth',
    success: entry.success,
    ipAddress: request.ip,
    userAgent: request.headers['user-agent'] || null,
    metadata: entry.metadata,
  });
}

function sendHtml(reply: FastifyReply, body: string, statusCode?: number): FastifyReply {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  if (statusCode !== undefined) reply.code(statusCode);
  return reply.send(body);
}

export default async function (fastify: FastifyInstance) {
  // Registration gate (#232 / #299), identical in shape to the `direct_post`
  // endpoint's: a deployment that never opted into wallet federation answers
  // 404 for these paths. An entry point that does not exist cannot be probed.
  if (!env.WALLET_FEDERATION_ENABLED) {
    fastify.log.debug('wallet-login UI not registered (WALLET_FEDERATION_ENABLED is off)');
    return;
  }

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-login',
    {
      schema: {
        description:
          'Renders the wallet sign-in screen, which collects the account identifier the user asserts (ADR-009). Issue #239.',
        tags: ['UI'],
        querystring: z.object({
          return_to: z.string().optional(),
          error: z.string().optional(),
        }),
      },
    },
    async (request, reply) => {
      const q = request.query as { return_to?: string; error?: string };
      const returnTo = resolveReturnTo(q.return_to);

      if (resolveWalletLoginCapability(fastify) === undefined) {
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Wallet sign-in is not available',
            message: 'This server is not currently accepting wallet credentials.',
            returnTo,
            retry: false,
          }),
          404
        );
      }

      // Same signed double-submit login-CSRF cookie the password form uses, and
      // reused rather than re-minted so a user who opens both screens keeps one
      // consistent token.
      const existing = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      const csrfToken = existing ?? generateCsrfToken();
      if (!existing) setLoginCsrfCookie(reply, csrfToken);

      return sendHtml(
        reply,
        identifierPage({
          returnTo,
          cspNonce: reply.cspNonce.style,
          csrfToken,
          error: q.error,
        })
      );
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/wallet-login',
    {
      schema: {
        description:
          'Starts a wallet sign-in: records the asserted account identifier and issues an OID4VP presentation request. Issue #239.',
        tags: ['UI'],
        body: walletLoginFormSchema,
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
      const body = request.body as WalletLoginForm;
      const returnTo = resolveReturnTo(body.return_to);

      const capability = resolveWalletLoginCapability(fastify);
      if (capability === undefined) {
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Wallet sign-in is not available',
            message: 'This server is not currently accepting wallet credentials.',
            returnTo,
            retry: false,
          }),
          404
        );
      }

      // Login CSRF, checked BEFORE anything else so a forged cross-site POST
      // cannot mint presentation requests (each of which is a DB row).
      const cookieCsrf = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      if (!cookieCsrf || !csrfTokensEqual(cookieCsrf, body.csrf_token)) {
        await fastify.repositories.auditLogs.create({
          userId: null,
          oauthClientId: null,
          event: 'ui.wallet_login.csrf_failure',
          eventType: 'auth',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: {},
        });
        const freshCsrf = generateCsrfToken();
        setLoginCsrfCookie(reply, freshCsrf);
        return sendHtml(
          reply,
          identifierPage({
            returnTo,
            cspNonce: reply.cspNonce.style,
            csrfToken: freshCsrf,
            error: 'Your session expired. Please try again.',
            identifier: body.identifier,
          }),
          403
        );
      }

      // NOT looked up. The identifier is an assertion, and checking whether it
      // exists here would turn this screen into an account oracle — every
      // submission must produce the same page.
      const assertedIdentifier = normalizeAssertedIdentifier(body.identifier);

      let handle: string;
      let invocationUri: string;
      try {
        const realm = await getOrCreateDefaultRealm(fastify);
        const invocation = buildWalletLoginInvocation(capability);

        await fastify.repositories.oid4vpRequestStates.create({
          realmId: realm.id,
          stateHash: invocation.stateHash,
          nonce: invocation.nonce,
          verifierProfile: capability.profile.id,
          responseMode: DIRECT_POST_RESPONSE_MODE,
          // Spread into a fresh object literal: the column is typed
          // `Record<string, unknown>` and an interface has no implicit index
          // signature. Nothing is reshaped — this is the query that was sent.
          dcqlQuery: { ...invocation.request.dcql_query },
          expiresAt: invocation.expiresAt,
        });

        const binder = generateWalletFlowSecret();
        handle = await createWalletLoginFlow(fastify, {
          stateHash: invocation.stateHash,
          assertedIdentifier,
          invocationUri: invocation.invocationUri,
          returnTo,
          binder,
          realmId: realm.id,
          verifierProfile: capability.profile.id,
          expiresAt: invocation.expiresAt,
          createdAt: Date.now(),
        });
        invocationUri = invocation.invocationUri;

        // ADDED to whatever this browser already holds rather than replacing
        // it: a user who starts a second sign-in while the first QR is still on
        // screen must keep both usable. See `WALLET_FLOW_COOKIE_NAME`.
        setWalletFlowCookie(reply, [
          ...readWalletFlowBindings(readCookie(request, WALLET_FLOW_COOKIE_NAME)),
          { handle, binder, expiresAt: invocation.expiresAt },
        ]);
      } catch (error) {
        // A profile that forbids what the request needs, an unreachable store, a
        // failed insert: all operator-visible, none of them the user's business.
        fastify.log.error({ err: error }, 'failed to start a wallet-login flow');
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Sign-in could not be started',
            message: WALLET_LOGIN_REFUSAL,
            returnTo,
            retry: true,
          }),
          500
        );
      }

      // The login-CSRF cookie has done its job for this flow; the browser binder
      // takes over from here.
      clearLoginCsrfCookie(reply);

      // Rendered directly rather than redirected to: the invocation is already
      // in hand, and a redirect would cost the user a round trip before the QR
      // appears. The price is that this page is a POST RESPONSE BODY — reloading
      // it re-POSTs and starts a NEW flow. `GET /ui/wallet-login/:handle` is the
      // URL that re-renders THIS flow from its record, which is why the noscript
      // block links there.
      return sendHtml(
        reply,
        pendingPage({
          handle,
          invocationUri,
          cspNonce: reply.cspNonce.style,
          scriptNonce: reply.cspNonce.script,
          returnTo,
        })
      );
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-login/:handle',
    {
      schema: {
        description:
          'Re-renders a wallet sign-in in progress, advancing it if the wallet has responded. Also the no-JavaScript refresh path. Issue #239.',
        tags: ['UI'],
        params: z.object({ handle: z.string() }),
      },
      config: {
        rateLimit: {
          max: WALLET_LOGIN_STATUS_RATE_LIMIT,
          timeWindow: WALLET_LOGIN_STATUS_RATE_WINDOW_S * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const { handle } = request.params as { handle: string };
      if (!isWalletLoginHandle(handle)) {
        return sendHtml(
          reply,
          terminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Sign-in request expired',
            message: WALLET_LOGIN_EXPIRED,
            returnTo: '/',
            retry: true,
          }),
          404
        );
      }

      const outcome = await advanceWalletLoginFlow(fastify, request, reply, handle);

      switch (outcome.status) {
        case 'complete':
          reply.header('Cache-Control', 'no-store');
          return reply.redirect(outcome.redirectTo, 302);
        case 'pending':
          return sendHtml(
            reply,
            pendingPage({
              handle,
              invocationUri: outcome.flow.invocationUri,
              cspNonce: reply.cspNonce.style,
              scriptNonce: reply.cspNonce.script,
              returnTo: outcome.flow.returnTo,
            })
          );
        case 'rejected':
          return sendHtml(
            reply,
            terminalPage({
              cspNonce: reply.cspNonce.style,
              title: 'Sign-in was not completed',
              message: WALLET_LOGIN_REFUSAL,
              returnTo: '/',
              retry: true,
            }),
            401
          );
        default:
          return sendHtml(
            reply,
            terminalPage({
              cspNonce: reply.cspNonce.style,
              title: 'Sign-in request expired',
              message: WALLET_LOGIN_EXPIRED,
              returnTo: '/',
              retry: true,
            }),
            410
          );
      }
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-login/:handle/status',
    {
      schema: {
        description:
          'Polled by the wallet sign-in screen. Reports whether the direct_post presentation response has arrived, and completes the sign-in when it has. Issue #239.',
        tags: ['UI'],
        params: z.object({ handle: z.string() }),
        response: { 200: walletLoginStatusSchema },
      },
      config: {
        // Sized for polling; see WALLET_LOGIN_STATUS_RATE_LIMIT for why the
        // global default is the wrong shape here.
        rateLimit: {
          max: WALLET_LOGIN_STATUS_RATE_LIMIT,
          timeWindow: WALLET_LOGIN_STATUS_RATE_WINDOW_S * 1000,
          keyGenerator: (request) => request.ip || 'unknown',
        },
      },
    },
    async (request, reply) => {
      const { handle } = request.params as { handle: string };
      reply.header('Cache-Control', 'no-store');

      if (!isWalletLoginHandle(handle)) {
        return reply.send({ status: 'expired', message: WALLET_LOGIN_EXPIRED });
      }

      const outcome = await advanceWalletLoginFlow(fastify, request, reply, handle);

      switch (outcome.status) {
        case 'complete':
          return reply.send({ status: 'complete', redirect_to: outcome.redirectTo });
        case 'pending':
          return reply.send({ status: 'pending' });
        case 'rejected':
          return reply.send({ status: 'rejected', message: WALLET_LOGIN_REFUSAL });
        default:
          return reply.send({ status: 'expired', message: WALLET_LOGIN_EXPIRED });
      }
    }
  );
}
