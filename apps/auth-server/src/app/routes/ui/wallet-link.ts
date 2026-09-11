import type { FastifyInstance, FastifyReply } from 'fastify';
import { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../../config/env';
import {
  WALLET_LOGIN_POLL_INTERVAL_MS,
  WALLET_LOGIN_STATUS_RATE_LIMIT,
  WALLET_LOGIN_STATUS_RATE_WINDOW_S,
} from '../../constants';
import { resolveBrowserSession } from '../../helpers/browser-session';
import { html, render, safe, safeCustomSchemeUrl } from '../../helpers/html';
import { encodeQrCode, renderQrCodeSvg } from '../../helpers/qr-code';
import {
  clearLoginCsrfCookie,
  csrfTokensEqual,
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  setLoginCsrfCookie,
  verifyLoginCsrfCookie,
} from '../../helpers/session-cookie';
import {
  advanceWalletLinkFlow,
  startWalletLinkFlow,
  WALLET_LINK_CONFLICT,
  WALLET_LINK_EXPIRED,
  WALLET_LINK_REFUSAL,
  WALLET_LINK_UNAVAILABLE,
} from '../../helpers/wallet-link-flow';
import { isWalletLoginHandle } from '../../helpers/wallet-login-flow';
import { resolveWalletLoginCapability } from '../../helpers/wallet-login-request';
import {
  WALLET_LINK_CONFLICT_TITLE,
  WALLET_LINK_EXPIRED_TITLE,
  WALLET_LINK_REJECTED_TITLE,
  walletLinkedPage,
  walletLinkTerminalPage,
  walletPageStyles,
} from '../../helpers/wallet-ui';

/**
 * Server-rendered WALLET LINKING screens (issue #238, ADR-004 / ADR-009 §5).
 *
 * The UI affordance for #238's task list, and a deliberately thin one: it is the
 * wallet-login screens minus the identifier field, plus a session requirement.
 *
 * ## No identifier field, and that is the whole difference
 *
 * The login screen has one because ADR-009 §1 leaves it no choice — there is no
 * usernameless wallet login, so the user must say which account they mean. Here
 * the account is the session's. Adding a field would create a second answer to
 * "which account?" that could disagree with the cookie, which is precisely the
 * ambiguity `session-binding` exists to remove.
 *
 * ## Signed in, or nothing
 *
 * Every screen requires a live session and redirects to the password login
 * otherwise. A linking flow started without one would have no account to bind
 * to, and a presentation that could attach itself to an account is ADR-009 §1's
 * second bootstrap case — the takeover this whole design refuses.
 *
 * ## Polling
 *
 * The page polls `GET /auth/link/wallet/:handle`, the JSON API in
 * `routes/auth/link-wallet.ts`, rather than a second status endpoint of its own.
 * One completion path, one set of gates; two would be two places for the session
 * re-check to be forgotten.
 *
 * ## Same device or another device — the user says which (#405, ADR-013)
 *
 * The confirmation form ends in TWO submit buttons, `device=other` ("Scan with
 * a wallet on another device") and `device=this` ("Use a wallet on this
 * device"), exactly as the wallet sign-in form does and for the same reason:
 * the two flows END differently. A same-device link completes on the return
 * leg — the wallet is handed a `redirect_uri` with a Response Code and brings
 * the browser to `/ui/wallet-login/return`, which dispatches on the flow's
 * mode — and never by polling (OID4VP 1.0 §14.2; HAIP 1.0 §5.1). A
 * cross-device link completes by polling exactly as before. So the pending
 * page renders exactly ONE affordance per flow, and the choice is recorded at
 * start in both records (`helpers/wallet-link-flow.ts`). An absent field is
 * cross-device, so every existing client and harness keeps the QR path it had.
 * The terminal pages moved to `helpers/wallet-ui.ts` so the return route
 * renders the same outcome bytes this page does.
 */

/**
 * Confirmation screen — a CSRF-protected POST starts the flow.
 *
 * Two submit buttons on the one form, named `device` (#405): the button the
 * user taps IS the same-device choice. Both are plain submits, so a browser
 * with scripts off makes the same choice the same way. The first button in
 * source order is the cross-device one on purpose — it is the path every
 * deployment served before #405, and the one that cannot strand a user on a
 * device with no wallet.
 */
function confirmPage(opts: { cspNonce: string; csrfToken: string; error?: string }): string {
  const { cspNonce, csrfToken, error } = opts;
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Link a wallet credential — QAuth</title>
          ${walletPageStyles(cspNonce)}
        </head>
        <body>
          <form class="card" method="post" action="/ui/wallet-link">
            <h1>Link a wallet credential</h1>
            ${error ? html`<div class="error" role="alert">${error}</div>` : ''}
            <p>
              Present a credential from your wallet to add it to the account you are signed in to.
              You will be able to sign in with either afterwards.
            </p>
            <input type="hidden" name="csrf_token" value="${csrfToken}" />
            <p class="hint">
              Your wallet does not tell us who you are, so this only works while you are signed in.
            </p>
            <button type="submit" name="device" value="other">
              Scan with a wallet on another device
            </button>
            <button type="submit" name="device" value="this" class="secondary">
              Use a wallet on this device
            </button>
            <p class="hint" id="device-hint">
              Choose where your wallet is: scanning shows a code for a wallet on your phone; using
              this device opens a wallet installed here and brings you back when you're done.
            </p>
            <a class="footer-link" href="/">Cancel</a>
          </form>
        </body>
      </html>`
  );
}

/**
 * The wallet invocation, plus the wait.
 *
 * Exactly one affordance (#405): a same-device flow renders the "Open my
 * wallet" anchor and NO QR; a cross-device flow renders the QR and NO anchor.
 * The two are not interchangeable once the flow has started — see the
 * `pendingPage` JSDoc in `wallet-login.ts`, which this mirrors — so each
 * variant gets a "Start again" footer link to `/ui/wallet-link`, which begins
 * a FRESH flow with the other choice available. The anchor is a plain
 * user-gesture `href` through `safeCustomSchemeUrl()`, exactly as before; the
 * QR degrades to an explanation past `QR_MAX_BYTES` rather than to a deep
 * link a scanning device could not use.
 */
function pendingPage(opts: {
  handle: string;
  invocationUri: string;
  sameDevice: boolean;
  cspNonce: string;
  scriptNonce: string;
}): string {
  const { handle, invocationUri, sameDevice, cspNonce, scriptNonce } = opts;
  const statusPath = `/auth/link/wallet/${handle}`;

  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>Waiting for your wallet — QAuth</title>
          ${walletPageStyles(cspNonce)}
        </head>
        <body>
          <div class="card">
            <h1>Present a credential</h1>
            ${sameDevice ? sameDeviceInvocation(invocationUri) : crossDeviceInvocation(invocationUri)}
            <div class="status" id="wallet-status" role="status" aria-live="polite">
              ${
                sameDevice
                  ? "Opening your wallet on this device… When you're done, your wallet will bring you back here."
                  : 'Waiting for your wallet…'
              }
            </div>
            <noscript>
              <p class="hint">
                This page updates itself when JavaScript is enabled.
                <a href="/ui/wallet-link/${handle}">Check whether your wallet has responded</a>.
              </p>
            </noscript>
            <a class="footer-link" href="/ui/wallet-link">Start again</a>
            <a class="footer-link" href="/">Cancel</a>
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

/**
 * The same-device half of the pending page: the "Open my wallet" anchor.
 * `safeCustomSchemeUrl()` rather than `safeUrl()` because the href is
 * `openid4vp://…` by design; when it refuses, the page renders an explanation
 * and no href at all.
 */
function sameDeviceInvocation(invocationUri: string) {
  const deepLink = safeCustomSchemeUrl(invocationUri);
  return html`<p>Open your wallet on this device to present a credential.</p>
    ${
      deepLink === undefined
        ? html`<p class="hint">
            This deployment cannot offer an open-my-wallet link. Contact your administrator.
          </p>`
        : html`<a class="alt-action" href="${deepLink}">Open my wallet</a>`
    }`;
}

/** The cross-device half of the pending page: the QR code. */
function crossDeviceInvocation(invocationUri: string) {
  const qr = encodeQrCode(invocationUri);
  return html`<p>Scan this code with the wallet on your other device.</p>
    ${
      qr === undefined
        ? html`<p class="hint">
            This request is too large to show as a code, so it cannot be scanned. Contact your
            administrator, or <a href="/ui/wallet-link">start again</a> and use a wallet on this
            device instead.
          </p>`
        : html`<div class="qr">
            ${safe(renderQrCodeSvg(qr, 'QR code containing the wallet linking request'))}
          </div>`
    }`;
}

const linkFormSchema = z.object({
  csrf_token: z.string().min(1),
  /**
   * Which submit button was pressed (#405): `this` opens a wallet on this
   * device and completes on the return leg; `other` renders a QR and completes
   * by polling. Defaults to `other` so a body without the field — the E2E
   * harness, a client built before #405 — keeps the cross-device path it had.
   * `startWalletLinkFlow` ALSO treats anything but `'this'` as `other`, so the
   * default holds even for a caller that bypasses schema validation.
   */
  device: z.enum(['this', 'other']).default('other'),
});

type LinkForm = z.infer<typeof linkFormSchema>;

function sendHtml(reply: FastifyReply, body: string, statusCode?: number): FastifyReply {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  if (statusCode !== undefined) reply.code(statusCode);
  return reply.send(body);
}

/**
 * The terminal screen every linking outcome renders, with linking-specific
 * copy. Lives in `helpers/wallet-ui.ts` since #405 so the return route renders
 * the same bytes; aliased here so the handlers below read as they did.
 */
const linkTerminalPage = walletLinkTerminalPage;

export default async function (fastify: FastifyInstance) {
  // Registration gate (#232 / #299), identical to the login screens': a
  // deployment that never opted into wallet federation answers 404 for these
  // paths. An entry point that does not exist cannot be probed.
  if (!env.WALLET_FEDERATION_ENABLED) {
    fastify.log.debug('wallet-link UI not registered (WALLET_FEDERATION_ENABLED is off)');
    return;
  }

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-link',
    {
      schema: {
        description:
          'Renders the wallet-linking confirmation screen for the signed-in user. Issue #238.',
        tags: ['UI'],
      },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.header('Cache-Control', 'no-store');
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent('/ui/wallet-link')}`, 302);
      }

      if (resolveWalletLoginCapability(fastify) === undefined) {
        return sendHtml(
          reply,
          linkTerminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Wallet linking is not available',
            message: WALLET_LINK_UNAVAILABLE,
            retry: false,
          }),
          404
        );
      }

      const existing = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      const csrfToken = existing ?? generateCsrfToken();
      if (!existing) setLoginCsrfCookie(reply, csrfToken);

      return sendHtml(reply, confirmPage({ cspNonce: reply.cspNonce.style, csrfToken }));
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/wallet-link',
    {
      schema: {
        description:
          'Starts a wallet-linking flow for the signed-in user and issues an OID4VP presentation request. Issue #238.',
        tags: ['UI'],
        body: linkFormSchema,
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
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.header('Cache-Control', 'no-store');
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent('/ui/wallet-link')}`, 302);
      }

      const body = request.body as LinkForm;

      // Login CSRF, checked BEFORE anything else so a forged cross-site POST
      // cannot mint presentation requests (each of which is a DB row) against a
      // signed-in user's session.
      const cookieCsrf = verifyLoginCsrfCookie(readCookie(request, LOGIN_CSRF_COOKIE_NAME));
      if (!cookieCsrf || !csrfTokensEqual(cookieCsrf, body.csrf_token)) {
        await fastify.repositories.auditLogs.create({
          userId: session.userId,
          oauthClientId: null,
          event: 'auth.wallet_link.csrf_failure',
          eventType: 'security',
          success: false,
          ipAddress: request.ip,
          userAgent: request.headers['user-agent'] || null,
          metadata: { surface: 'ui' },
        });
        const freshCsrf = generateCsrfToken();
        setLoginCsrfCookie(reply, freshCsrf);
        return sendHtml(
          reply,
          confirmPage({
            cspNonce: reply.cspNonce.style,
            csrfToken: freshCsrf,
            error: 'Your session expired. Please try again.',
          }),
          403
        );
      }

      let started;
      try {
        // The device choice is the user's own form submission (#405); the
        // helper records it on both the row and the flow record, and reports
        // back what it recorded so the page renders the matching affordance.
        started = await startWalletLinkFlow(fastify, request, reply, session.userId, {
          device: body.device,
        });
      } catch (error) {
        fastify.log.error({ err: error }, 'failed to start a wallet-link flow');
        return sendHtml(
          reply,
          linkTerminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Linking could not be started',
            message: WALLET_LINK_REFUSAL,
            retry: true,
          }),
          500
        );
      }

      if (started === undefined) {
        return sendHtml(
          reply,
          linkTerminalPage({
            cspNonce: reply.cspNonce.style,
            title: 'Wallet linking is not available',
            message: WALLET_LINK_UNAVAILABLE,
            retry: false,
          }),
          404
        );
      }

      clearLoginCsrfCookie(reply);

      return sendHtml(
        reply,
        pendingPage({
          handle: started.handle,
          invocationUri: started.invocationUri,
          sameDevice: started.sameDevice,
          cspNonce: reply.cspNonce.style,
          scriptNonce: reply.cspNonce.script,
        })
      );
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/wallet-link/:handle',
    {
      schema: {
        description:
          'Re-renders a wallet-linking flow in progress, completing it if the wallet has responded. Also the no-JavaScript refresh path. Issue #238.',
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
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.header('Cache-Control', 'no-store');
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent('/ui/wallet-link')}`, 302);
      }

      const { handle } = request.params as { handle: string };
      if (!isWalletLoginHandle(handle)) {
        return sendHtml(
          reply,
          linkTerminalPage({
            cspNonce: reply.cspNonce.style,
            title: WALLET_LINK_EXPIRED_TITLE,
            message: WALLET_LINK_EXPIRED,
            retry: true,
          }),
          404
        );
      }

      const outcome = await advanceWalletLinkFlow(fastify, request, reply, handle, session.userId, {
        via: 'poll',
      });

      switch (outcome.status) {
        case 'pending': {
          return sendHtml(
            reply,
            pendingPage({
              handle,
              invocationUri: outcome.flow.invocationUri,
              sameDevice: outcome.flow.sameDevice === true,
              cspNonce: reply.cspNonce.style,
              scriptNonce: reply.cspNonce.script,
            })
          );
        }
        case 'linked':
          return sendHtml(
            reply,
            walletLinkedPage({ cspNonce: reply.cspNonce.style, rebound: outcome.rebound })
          );
        case 'conflict':
          return sendHtml(
            reply,
            linkTerminalPage({
              cspNonce: reply.cspNonce.style,
              title: WALLET_LINK_CONFLICT_TITLE,
              message: WALLET_LINK_CONFLICT,
              retry: false,
            }),
            409
          );
        case 'rejected':
          return sendHtml(
            reply,
            linkTerminalPage({
              cspNonce: reply.cspNonce.style,
              title: WALLET_LINK_REJECTED_TITLE,
              message: WALLET_LINK_REFUSAL,
              retry: true,
            }),
            401
          );
        default:
          return sendHtml(
            reply,
            linkTerminalPage({
              cspNonce: reply.cspNonce.style,
              title: WALLET_LINK_EXPIRED_TITLE,
              message: WALLET_LINK_EXPIRED,
              retry: true,
            }),
            410
          );
      }
    }
  );
}
