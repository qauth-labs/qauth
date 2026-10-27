import type { FastifyReply } from 'fastify';

import { html, render, type SafeHtml } from './html';

/**
 * The page behind the emailed verification link (`GET /auth/verify?token=…`)
 * and the answers of its form (`POST /ui/verify`).
 *
 * Server-rendered like `/ui/login`: no script, one inline `<style>` carrying
 * the per-request CSP nonce, and nothing loaded from anywhere else. The form
 * posts to `/ui/verify` and works without JavaScript.
 *
 * Interim: the email-code step (#638) and the hosted account verification UI
 * (#644) replace link verification and this page.
 */

/** Where the form posts. */
export const VERIFY_FORM_ACTION = '/ui/verify';

/** What the page shows. */
export type VerifyEmailPageState =
  /** The form: the token in a hidden field, and the password to type. */
  | {
      readonly kind: 'form';
      /** The mailed token, already format-checked. */
      readonly token: string;
      /** Signed double-submit CSRF token; mirrored in the `__Host-` login-CSRF cookie. */
      readonly csrfToken: string;
      /** A fixed refusal text from the server. Never caller-supplied text. */
      readonly error?: string;
    }
  /** The link carries no token, or not one of the right shape. Nothing was looked up. */
  | { readonly kind: 'incomplete-link' }
  /** The token is unknown, expired or used: one page for all of them. */
  | { readonly kind: 'invalid-link' }
  /** Verified just now. */
  | { readonly kind: 'verified'; readonly email: string }
  /** The address was already verified. */
  | { readonly kind: 'already-verified' };

/** The refusal texts of the form, one per answer of the verification. */
export const VERIFY_FORM_ERRORS = {
  /** A wrong password: the token is not consumed, so the form stays. */
  wrongPassword: 'That password does not match this account.',
  /** The failed-login lockout the password check shares with the login routes. */
  lockedOut: 'Too many failed attempts. Please try again later.',
  /** The CSRF pair was missing or did not match. */
  sessionExpired: 'Your session expired. Please try again.',
} as const;

function content(state: VerifyEmailPageState): { title: string; body: SafeHtml } {
  switch (state.kind) {
    case 'form':
      return {
        title: 'Confirm your email address',
        body: html`<form method="post" action="${VERIFY_FORM_ACTION}">
          <h1>Confirm your email address</h1>
          ${state.error ? html`<div class="error" role="alert">${state.error}</div>` : ''}
          <p>
            Someone used this email address to create an account. If that was you, enter the
            password you chose for it.
          </p>
          <p>
            If it was not you, close this page. Without that password the address stays unverified.
          </p>
          <input type="hidden" name="token" value="${state.token}" />
          <input type="hidden" name="csrf_token" value="${state.csrfToken}" />
          <label>
            Password
            <input type="password" name="password" autocomplete="current-password" required />
          </label>
          <button type="submit">Confirm email address</button>
        </form>`,
      };
    case 'incomplete-link':
      return {
        title: 'This link is incomplete',
        body: html`<h1>This link is incomplete</h1>
          <p>
            The verification link is missing its code, or part of it was lost. Open the link from
            the email again, or copy the whole link into your browser.
          </p>`,
      };
    case 'invalid-link':
      return {
        title: 'This link is no longer valid',
        body: html`<h1>This link is no longer valid</h1>
          <p>
            The verification link has expired or has already been used. Ask the application you
            registered with to send a new verification email.
          </p>`,
      };
    case 'verified':
      return {
        title: 'Email address verified',
        body: html`<h1>Email address verified</h1>
          <p><strong>${state.email}</strong> is verified.</p>
          <p>You can now sign in to the application you registered with.</p>`,
      };
    case 'already-verified':
      return {
        title: 'Email address already verified',
        body: html`<h1>Email address already verified</h1>
          <p>
            This email address is already verified. You can sign in to the application you
            registered with.
          </p>`,
      };
  }
}

/**
 * Render the page for `state`.
 *
 * @param state - what to show.
 * @param cspNonce - the per-request style nonce (`reply.cspNonce.style`, #113).
 */
export function verifyEmailPage(state: VerifyEmailPageState, cspNonce: string): string {
  const { title, body } = content(state);
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
            }
            label {
              display: block;
              margin-top: 16px;
              font-size: 13px;
              font-weight: 600;
            }
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
          <main class="card">${body}</main>
        </body>
      </html>`
  );
}

/**
 * Send the page with the headers every answer of the verification page carries.
 *
 * - `Cache-Control: no-store`: the form holds the token and a CSRF value.
 * - `Referrer-Policy: no-referrer`, set here as well as by the global
 *   security headers (#113): the page's URL carries the token, and it must not
 *   reach any other origin in a `Referer` header even if that default changes.
 *
 * @param reply - the reply to answer on.
 * @param statusCode - the status, the same as `POST /auth/verify` answers for the same outcome.
 * @param state - what to show.
 */
export function sendVerifyEmailPage(
  reply: FastifyReply,
  statusCode: number,
  state: VerifyEmailPageState
): FastifyReply {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  reply.header('Referrer-Policy', 'no-referrer');
  reply.code(statusCode);
  return reply.send(verifyEmailPage(state, reply.cspNonce.style));
}
