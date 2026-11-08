import type { FastifyReply } from 'fastify';

/**
 * THE `form-action` OF A PAGE WHOSE FORM'S ANSWER LEAVES THE REALM ORIGIN.
 *
 * Every page carries `form-action 'self'` (plugins/security-headers.ts).
 * Chromium and WebKit apply `form-action` to the redirects that follow a
 * form post as well as to the post itself, so a form whose answer redirects
 * the browser to a client (a sign-in step that finishes an authorization and
 * sends `303` to its `redirect_uri`, a logout confirm that returns to the
 * app) is blocked there unless the page also allows that destination. The
 * page adds exactly one source: the destination's origin for a web URI, its
 * scheme for a native app's. Firefox does not check the redirects, which is
 * why the gap did not show in every browser.
 */

/** A CSP source expression of a URL's origin, or of a native app's scheme; `undefined` for anything else. */
const CSP_SOURCE = /^(?:[a-z][a-z0-9+.-]*:\/\/[A-Za-z0-9.\-[\]:]+|[a-z][a-z0-9+.-]*:)$/;

/**
 * The CSP source a form whose answer may redirect to `uri` must allow: its
 * origin for a web URI, its scheme for a native app's. `undefined` when the
 * URI yields no source this module can write safely.
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
 * Allow `source` (from {@link formActionSourceOf}) in the reply's
 * `form-action`, beside the page's own origin. Nothing changes for an
 * `undefined` source, or a reply whose policy names no `form-action 'self'`.
 */
export function allowFormActionTo(reply: FastifyReply, source: string | undefined): void {
  if (source === undefined || !CSP_SOURCE.test(source)) return;
  const csp = reply.getHeader('content-security-policy');
  if (typeof csp !== 'string' || !csp.includes("form-action 'self'")) return;
  if (csp.includes(`form-action 'self' ${source}`)) return;
  reply.header(
    'Content-Security-Policy',
    csp.replace("form-action 'self'", `form-action 'self' ${source}`)
  );
}
