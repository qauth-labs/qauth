import type { FastifyReply } from 'fastify';

import { html, render } from './html';
import { walletPageStyles } from './wallet-ui';

/**
 * THE UPSTREAM SIGN-IN FLOW'S PAGES (#639), server-rendered in the current
 * `/ui` style, as `/ui/login` is: each works without JavaScript. The
 * design-system screens of the ceremony app (#618) replace them later.
 *
 * - The waiting page: the browser goes on to the provider at once (a meta
 *   refresh), with a link for a browser that does not follow it and a way
 *   back to the first sign-in step.
 * - The provider-error page: the person cancelled or declined at the
 *   provider, or the provider answered an error. Nothing goes to the
 *   client's redirect URI: the person has not refused the client's request,
 *   and the way back leads to the first sign-in step, where they may pick
 *   another way.
 * - The error page: every other failure, with one text and the request's
 *   trace id, so support can find the log line without the page telling
 *   what failed.
 *
 * None of them shows anything the request carried but the provider's name,
 * as the operator set it, and the trace id.
 */

/** The page's chrome: the shared `/ui` styles under the request's CSP nonce. */
function page(opts: {
  readonly cspNonce: string;
  readonly title: string;
  readonly head?: ReturnType<typeof html>;
  readonly body: ReturnType<typeof html>;
}): string {
  return render(
    html`<!doctype html>
      <html lang="en">
        <head>
          <meta charset="utf-8" />
          <meta name="viewport" content="width=device-width,initial-scale=1" />
          <meta name="robots" content="noindex" />
          <meta name="referrer" content="no-referrer" />
          ${opts.head ?? ''}
          <title>${opts.title} — QAuth</title>
          ${walletPageStyles(opts.cspNonce)}
        </head>
        <body>
          <main class="card">${opts.body}</main>
        </body>
      </html>`
  );
}

/** The waiting page's title. */
export const UPSTREAM_WAITING_TITLE = 'Continuing to your sign-in provider';

/**
 * The waiting page: on to the provider's authorization request at once, a
 * link for the browser that does not follow the refresh, and the way back.
 */
export function upstreamWaitingPage(opts: {
  readonly cspNonce: string;
  readonly providerName: string;
  /** The provider's authorization request: an absolute `https` URL `startUpstreamStep` checked. */
  readonly redirectTo: string;
  /** The first sign-in step. */
  readonly wayBack: string;
}): string {
  const { cspNonce, providerName, redirectTo, wayBack } = opts;
  return page({
    cspNonce,
    title: UPSTREAM_WAITING_TITLE,
    head: html`<meta http-equiv="refresh" content="0;url=${redirectTo}" />`,
    body: html`<h1>${UPSTREAM_WAITING_TITLE}</h1>
      <p role="status">Taking you to ${providerName} to sign in.</p>
      <a class="alt-action" href="${redirectTo}">Continue to ${providerName}</a>
      <a class="footer-link" href="${wayBack}">Choose another way to sign in</a>`,
  });
}

/** The provider-error page's title. */
export const UPSTREAM_PROVIDER_ERROR_TITLE = 'Sign-in was not completed';

/**
 * The provider-error page: the person cancelled or declined at the
 * provider, or the provider answered an error. The way back is the first
 * sign-in step.
 */
export function upstreamProviderErrorPage(opts: {
  readonly cspNonce: string;
  readonly providerName: string;
  readonly wayBack: string;
}): string {
  const { cspNonce, providerName, wayBack } = opts;
  return page({
    cspNonce,
    title: UPSTREAM_PROVIDER_ERROR_TITLE,
    body: html`<h1>${UPSTREAM_PROVIDER_ERROR_TITLE}</h1>
      <p role="alert">
        ${providerName} did not sign you in. You may have cancelled there, or ${providerName} could
        not complete the sign-in.
      </p>
      <a class="alt-action" href="${wayBack}">Choose another way to sign in</a>`,
  });
}

/** The error page's title. */
export const UPSTREAM_ERROR_TITLE = 'We could not sign you in';

/**
 * The one error page of the flow: the same text for every failure, and the
 * trace id of the request. The way back, when the flow knows one.
 */
export function upstreamErrorPage(opts: {
  readonly cspNonce: string;
  readonly traceId: string;
  readonly wayBack?: string;
}): string {
  const { cspNonce, traceId, wayBack } = opts;
  return page({
    cspNonce,
    title: UPSTREAM_ERROR_TITLE,
    body: html`<h1>${UPSTREAM_ERROR_TITLE}</h1>
      <p role="alert">Something went wrong while signing you in. Please start again.</p>
      <p class="hint">If you contact support, give them this trace id: <code>${traceId}</code></p>
      ${
        wayBack === undefined
          ? ''
          : html`<a class="alt-action" href="${wayBack}">Start signing in again</a>`
      }`,
  });
}

/** Send one of the pages: HTML, never cached. */
export function sendUpstreamPage(
  reply: FastifyReply,
  body: string,
  statusCode = 200
): FastifyReply {
  reply.header('Content-Type', 'text/html; charset=utf-8');
  reply.header('Cache-Control', 'no-store');
  reply.code(statusCode);
  return reply.send(body);
}
