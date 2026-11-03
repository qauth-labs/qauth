import type { ClientDisplay } from '@qauth-labs/shared-interaction-client';
import type { FastifyReply } from 'fastify';

import { html, render, safe, type SafeHtml } from './html';

/**
 * The pages of RP-initiated logout (#675, `graphs/flows/core/logout`): what
 * the end-session route and its status page show in the browser.
 *
 * Server-rendered like `/ui/login`: no script, one inline `<style>` carrying
 * the per-request CSP nonce, and nothing loaded from anywhere else. The
 * confirm form posts its answer to the Interaction API and works without
 * JavaScript; it is drawn here only while `INTERACTION_UI_ENABLED` is off,
 * when no ceremony app draws the `logout_confirm` step.
 *
 * No page shows anything the request carried: the refusal names no
 * parameter, and the status page takes none.
 */

/** What a page shows. */
export type EndSessionPage =
  /**
   * The `logout_confirm` step as a plain form: the account it signs out, the
   * app that asked when the request named one, and the three decisions.
   */
  | {
      readonly kind: 'confirm';
      /** Where the form posts: the Interaction API's answer of this interaction. */
      readonly action: string;
      /** The step's URN, the answer's `type`. */
      readonly step: string;
      /** The CSRF value of the step view. */
      readonly csrf: string;
      /** The account signed in on this browser, by the identifier it signed in with. */
      readonly identifier: string;
      /** Who the app is, when the request named a client. */
      readonly client?: ClientDisplay;
    }
  /** The browser holds no session of the realm now. */
  | { readonly kind: 'signed_out' }
  /** The status page, while the browser still holds a session. */
  | { readonly kind: 'signed_in' }
  /**
   * Signed out, and the app's registered return URI offered as a link rather
   * than a redirect: the app was not set up by the operator.
   */
  | {
      readonly kind: 'leaving';
      /** The host the link goes to. */
      readonly host: string;
      /** The link, only for an http(s) URI (`safeUrl`); a native app's scheme gets none. */
      readonly href: string | undefined;
    }
  /** A refused request: nothing ended, and the browser is not redirected. */
  | { readonly kind: 'refused'; readonly traceId: string };

/** The app as the confirm page names it: its verified domain first, then its declared name. */
function appOf(client: ClientDisplay): SafeHtml {
  const domain = client.verifiedDomain?.host;
  const declared = client.declaredName;
  if (domain !== undefined && declared !== undefined) {
    return html`<strong>${declared}</strong> (${domain})`;
  }
  if (domain !== undefined) return html`<strong>${domain}</strong>`;
  if (declared !== undefined) {
    return html`<strong>${declared}</strong> (a name the app gave itself)`;
  }
  return html`An app`;
}

function content(page: EndSessionPage): { title: string; body: SafeHtml } {
  switch (page.kind) {
    case 'confirm':
      return {
        title: 'Sign out?',
        body: html`<form method="post" action="${page.action}">
          <h1>Sign out?</h1>
          ${
            page.client === undefined
              ? html`<p>A sign-out was requested for this browser.</p>`
              : html`<p>${appOf(page.client)} asks to sign you out.</p>`
          }
          <p>Signed in as <strong>${page.identifier}</strong>.</p>
          <input type="hidden" name="type" value="${page.step}" />
          <input type="hidden" name="csrf" value="${page.csrf}" />
          <button type="submit" name="decision" value="logout">Sign out</button>
          <button type="submit" name="decision" value="logout_all" class="secondary">
            Sign out of all accounts
          </button>
          <button type="submit" name="decision" value="stay" class="secondary">
            Stay signed in
          </button>
        </form>`,
      };
    case 'signed_out':
      return {
        title: 'You are signed out',
        body: html`<h1>You are signed out</h1>
          <p>This browser is no longer signed in. You can close this page.</p>`,
      };
    case 'leaving':
      return {
        title: 'You are signed out',
        body: html`<h1>You are signed out</h1>
          <p>This browser is no longer signed in.</p>
          <p>
            The app that asked was not set up by the operator of this server, so you are not sent
            back to it automatically. Continue only if you expected to return to
            <strong>${page.host}</strong>.
          </p>
          ${
            page.href === undefined
              ? safe('')
              : html`<p>
                  <a href="${page.href}" rel="noopener noreferrer">Continue to ${page.host}</a>
                </p>`
          }`,
      };
    case 'signed_in':
      return {
        title: 'You are still signed in',
        body: html`<h1>You are still signed in</h1>
          <p>This browser is still signed in. Nothing was signed out.</p>`,
      };
    case 'refused':
      return {
        title: 'This sign-out request is not valid',
        body: html`<h1>This sign-out request is not valid</h1>
          <p>
            The app sent a sign-out request that cannot be carried out. Nothing was changed: if you
            were signed in, you still are.
          </p>
          <p class="reference">Reference: ${page.traceId}</p>`,
      };
  }
}

/**
 * Render a page.
 *
 * @param page - what to show.
 * @param cspNonce - the per-request style nonce (`reply.cspNonce.style`, #113).
 */
export function endSessionPage(page: EndSessionPage, cspNonce: string): string {
  const { title, body } = content(page);
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${title} — QAuth</title>
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
              max-width: 420px;
            }
            h1 {
              margin: 0 0 16px;
              font-size: 20px;
            }
            p {
              margin: 0 0 8px;
              font-size: 14px;
              line-height: 1.5;
              color: #374151;
              overflow-wrap: anywhere;
            }
            .reference {
              margin-top: 16px;
              font-size: 12px;
              color: #6b7280;
            }
            button {
              display: block;
              margin-top: 12px;
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
            button.secondary {
              background: #eef1f6;
              color: #1a1a1a;
            }
          </style>
        </head>
        <body>
          <main class="card">${body}</main>
        </body>
      </html>`
  );
}

/** A CSP source expression of a URL's origin, or of a native app's scheme; `undefined` for anything else. */
const CSP_SOURCE = /^(?:[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9.\-[\]:]+|[a-z][a-z0-9+.-]*:)$/;

/**
 * The CSP source a form whose answer may redirect to `uri` must allow: its
 * origin for a web URI, its scheme for a native app's. Chromium and WebKit
 * apply `form-action` to the redirects that follow a form post, so the
 * confirm form's `form-action 'self'` would block the redirect back to the
 * app. `undefined` when the URI yields no source this module can write safely.
 */
export function formActionSourceOf(uri: string): string | undefined {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return undefined;
  }
  const source = url.protocol === 'https:' || url.protocol === 'http:' ? url.origin : url.protocol;
  return CSP_SOURCE.test(source) ? source : undefined;
}

/**
 * Send a page with the headers every answer of these pages carries: HTML,
 * `Cache-Control: no-store` (the confirm form holds a CSRF value) and
 * `Referrer-Policy: no-referrer`, as the verification page sets it. A
 * confirm page whose answer may go back to an app allows that app's origin in
 * `form-action` beside the page's own ({@link formActionSourceOf}).
 *
 * @param reply - the reply to answer on.
 * @param statusCode - 200, or 400 for a refusal.
 * @param page - what to show.
 * @param returnTo - the registered URI the confirm form's answer may redirect to.
 */
export function sendEndSessionPage(
  reply: FastifyReply,
  statusCode: number,
  page: EndSessionPage,
  returnTo?: string
): FastifyReply {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  reply.header('Referrer-Policy', 'no-referrer');
  const source = returnTo === undefined ? undefined : formActionSourceOf(returnTo);
  const csp = reply.getHeader('content-security-policy');
  if (source !== undefined && typeof csp === 'string') {
    reply.header(
      'Content-Security-Policy',
      csp.replace("form-action 'self'", `form-action 'self' ${source}`)
    );
  }
  reply.code(statusCode);
  return reply.send(endSessionPage(page, reply.cspNonce.style));
}
