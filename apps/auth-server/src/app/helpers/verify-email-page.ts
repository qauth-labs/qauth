import type { FastifyReply } from 'fastify';

import { html, render, type SafeHtml } from './html';
import { uiStylesheetLink } from './ui-assets';

/**
 * The page behind the emailed verification link (`GET /auth/verify?token=…`)
 * and the answers of its form (`POST /ui/verify`).
 *
 * Server-rendered like `/ui/login`: no script, no inline style, the `/ui`
 * pages' stylesheet (#472), and nothing loaded from another origin. The form
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
  /** The failure ladder's store failed (#615): nothing was checked. */
  unavailable: 'Verification is unavailable right now. Please try again shortly.',
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
 */
export function verifyEmailPage(state: VerifyEmailPageState): string {
  const { title, body } = content(state);
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <title>${title} — QAuth</title>
          ${uiStylesheetLink()}
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
  return reply.send(verifyEmailPage(state));
}
