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
import { walletPageStyles, walletTerminalPage } from '../../helpers/wallet-ui';

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
 */

/** Confirmation screen — a CSRF-protected POST starts the flow. */
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
            <button type="submit">Continue</button>
            <a class="footer-link" href="/">Cancel</a>
          </form>
        </body>
      </html>`
  );
}

/** The wallet invocation, plus the wait. */
function pendingPage(opts: {
  handle: string;
  invocationUri: string;
  cspNonce: string;
  scriptNonce: string;
}): string {
  const { handle, invocationUri, cspNonce, scriptNonce } = opts;
  const qr = encodeQrCode(invocationUri);
  const deepLink = safeCustomSchemeUrl(invocationUri);
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
            <p>Scan this code with your wallet, or open your wallet on this device.</p>
            ${
              qr === undefined
                ? html`<p class="hint">
                    This request is too large to show as a code. Use the button below on the device
                    your wallet is installed on.
                  </p>`
                : html`<div class="qr">
                    ${safe(renderQrCodeSvg(qr, 'QR code containing the wallet linking request'))}
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
                <a href="/ui/wallet-link/${handle}">Check whether your wallet has responded</a>.
              </p>
            </noscript>
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

const linkFormSchema = z.object({ csrf_token: z.string().min(1) });

function sendHtml(reply: FastifyReply, body: string, statusCode?: number): FastifyReply {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  if (statusCode !== undefined) reply.code(statusCode);
  return reply.send(body);
}

/** The terminal screen every linking outcome renders, with linking-specific copy. */
function linkTerminalPage(opts: {
  cspNonce: string;
  title: string;
  message: string;
  retry: boolean;
}): string {
  return walletTerminalPage({
    cspNonce: opts.cspNonce,
    title: opts.title,
    message: opts.message,
    returnTo: '/',
    retry: opts.retry,
    retryHref: '/ui/wallet-link',
    footer: { href: '/', label: 'Back' },
  });
}

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

      const body = request.body as z.infer<typeof linkFormSchema>;

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
            title: 'Linking request expired',
            message: WALLET_LINK_EXPIRED,
            retry: true,
          }),
          404
        );
      }

      const outcome = await advanceWalletLinkFlow(fastify, request, reply, handle, session.userId);

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
            linkTerminalPage({
              cspNonce: reply.cspNonce.style,
              title: 'Wallet credential linked',
              message: outcome.rebound
                ? 'Your wallet credential was updated. You can sign in with it or with your password.'
                : 'Your wallet credential is now linked to this account. You can sign in with either.',
              retry: false,
            })
          );
        case 'conflict':
          return sendHtml(
            reply,
            linkTerminalPage({
              cspNonce: reply.cspNonce.style,
              title: 'Already linked elsewhere',
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
              title: 'Linking was not completed',
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
              title: 'Linking request expired',
              message: WALLET_LINK_EXPIRED,
              retry: true,
            }),
            410
          );
      }
    }
  );
}
