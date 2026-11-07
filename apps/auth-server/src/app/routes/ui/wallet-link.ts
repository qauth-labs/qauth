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
import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { requestRealm } from '../../helpers/request-realm';
import {
  clearLoginCsrfCookie,
  csrfTokensEqual,
  generateCsrfToken,
  LOGIN_CSRF_COOKIE_NAME,
  readCookie,
  setLoginCsrfCookie,
  verifyLoginCsrfCookie,
} from '../../helpers/session-cookie';
import { emitUserEvent } from '../../helpers/user-events';
import {
  advanceWalletLinkFlow,
  startWalletLinkFlow,
  WALLET_LINK_CONFLICT,
  WALLET_LINK_EXPIRED,
  WALLET_LINK_REFUSAL,
  WALLET_LINK_UNAVAILABLE,
} from '../../helpers/wallet-link-flow';
import { isWalletLoginHandle } from '../../helpers/wallet-login-flow';
import { resolveWalletLoginCapabilityIn } from '../../helpers/wallet-login-request';
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
 * ## Same device only (#405, ADR-013 as amended 2026-11-07)
 *
 * The confirmation form ends in ONE submit button, "Use a wallet on this
 * device" (`device=this`). A link completes only on the return leg — the
 * wallet is handed a `redirect_uri` with a Response Code and brings the
 * browser to `/ui/wallet-login/return`, which dispatches on the flow's mode —
 * and never by polling (OID4VP 1.0 §14.2; HAIP 1.0 §5.1). There is no QR code
 * and no "scan with a wallet on another device" button: linking is
 * same-device only. A form that still posts `device=other`
 * is refused by the body schema with `400` `validation_error`; an absent field
 * is same-device. A person whose wallet is on their phone opens this page on
 * the phone. The terminal pages moved to `helpers/wallet-ui.ts` so the return
 * route renders the same outcome bytes this page does.
 */

/**
 * Confirmation screen — a CSRF-protected POST starts the flow.
 *
 * One submit button (ADR-013 as amended 2026-11-07): a link is made only with
 * a wallet on this device. The button still names `device=this`, so the form
 * posts exactly what the schema accepts, and a browser with scripts off makes
 * the same request the same way.
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
            <button type="submit" name="device" value="this">Use a wallet on this device</button>
            <p class="hint" id="device-hint">
              This opens a wallet installed on this device and brings you back when you're done. If
              your wallet is on another device, such as your phone, sign in there and link it from
              that device.
            </p>
            <a class="footer-link" href="/">Cancel</a>
          </form>
        </body>
      </html>`
  );
}

/** What the pending page says while the wallet is open. */
const PENDING_STATUS =
  "Opening your wallet on this device… When you're done, your wallet will bring you back here.";

/**
 * The wallet invocation, plus the wait.
 *
 * Exactly one affordance: the "Open my wallet" anchor, and NO QR code — a
 * link is same-device only (ADR-013 as amended 2026-11-07). The anchor is a
 * plain user-gesture `href` through `safeCustomSchemeUrl()`, exactly as
 * before, and a "Start again" footer link to `/ui/wallet-link` begins a FRESH
 * flow. The page polls only so the original tab can render the outcome the
 * return leg reached (from its done-marker); the poll never completes a link.
 */
function pendingPage(opts: {
  handle: string;
  invocationUri: string;
  cspNonce: string;
  scriptNonce: string;
}): string {
  const { handle, invocationUri, cspNonce, scriptNonce } = opts;
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
            ${sameDeviceInvocation(invocationUri)}
            <div class="status" id="wallet-status" role="status" aria-live="polite">
              ${PENDING_STATUS}
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
 * The pending page's one affordance: the "Open my wallet" anchor.
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

const linkFormSchema = z.object({
  csrf_token: z.string().min(1),
  /**
   * The submit button's value: `this`, a wallet on this device, the one value
   * accepted (ADR-013 as amended 2026-11-07). `other` — the cross-device
   * button this form had before — is refused with `400` `validation_error`;
   * an absent field means `this`. `startWalletLinkFlow` takes no device at
   * all, so a caller that bypassed this schema still starts a same-device flow.
   */
  device: z
    .literal('this', {
      error:
        'Linking works only with a wallet on this device, so "device" must be "this" or left out.',
    })
    .optional(),
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
        'x-qauth-stability': 'experimental',
      },
      config: { surface: 'browser' },
    },
    async (request, reply) => {
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.header('Cache-Control', 'no-store');
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent('/ui/wallet-link')}`, 302);
      }

      if ((await resolveWalletLoginCapabilityIn(fastify, requestRealm(request))) === undefined) {
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

      const existing = await verifyLoginCsrfCookie(
        fastify,
        requestRealm(request).id,
        readCookie(request, LOGIN_CSRF_COOKIE_NAME)
      );
      const csrfToken = existing ?? generateCsrfToken();
      if (!existing) await setLoginCsrfCookie(fastify, reply, requestRealm(request).id, csrfToken);

      return sendHtml(reply, confirmPage({ cspNonce: reply.cspNonce.style, csrfToken }));
    }
  );

  fastify.withTypeProvider<ZodTypeProvider>().post(
    '/wallet-link',
    {
      schema: {
        description:
          'Starts a wallet-linking flow for the signed-in user and issues an OID4VP presentation request for a wallet on this device. Linking is same-device only (ADR-013, amended 2026-11-07): the form field `device` accepts only `this`, which is also what an absent field means, and `other` (cross-device) is refused with `400` `validation_error`. Issues #238, #405.',
        tags: ['UI'],
        'x-qauth-stability': 'experimental',
        'x-qauth-errors': [400],
        body: linkFormSchema,
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
      const session = await resolveBrowserSession(fastify, request, reply);
      if (!session) {
        reply.header('Cache-Control', 'no-store');
        return reply.redirect(`/ui/login?return_to=${encodeURIComponent('/ui/wallet-link')}`, 302);
      }

      const body = request.body as LinkForm;

      // Login CSRF, checked BEFORE anything else so a forged cross-site POST
      // cannot mint presentation requests (each of which is a DB row) against a
      // signed-in user's session.
      const cookieCsrf = await verifyLoginCsrfCookie(
        fastify,
        requestRealm(request).id,
        readCookie(request, LOGIN_CSRF_COOKIE_NAME)
      );
      if (!cookieCsrf || !csrfTokensEqual(cookieCsrf, body.csrf_token)) {
        await emitUserEvent(
          request,
          'urn:qauth:event:request.csrf_rejected:v1-rc.0',
          { form: 'wallet_link' },
          { userId: session.userId, actor: 'user' }
        );
        const freshCsrf = generateCsrfToken();
        await setLoginCsrfCookie(fastify, reply, requestRealm(request).id, freshCsrf);
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
        // Same-device, always: the helper takes no device (ADR-013 as amended
        // 2026-11-07), and the schema has refused every value but `this`.
        started = await startWalletLinkFlow(fastify, request, reply, session.userId);
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
        'x-qauth-stability': 'experimental',
        params: z.object({ handle: z.string() }),
      },
      config: {
        surface: 'browser',
        rateLimit: {
          max: WALLET_LOGIN_STATUS_RATE_LIMIT,
          timeWindow: WALLET_LOGIN_STATUS_RATE_WINDOW_S * 1000,
          keyGenerator: realmRateLimitKey,
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
