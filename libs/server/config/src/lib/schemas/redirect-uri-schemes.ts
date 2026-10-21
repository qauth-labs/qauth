import { z } from 'zod';

/**
 * An RFC 3986 §3.1 scheme name, lower-cased: a letter, then letters, digits,
 * `+`, `-` or `.`. Written without the trailing colon.
 */
const URI_SCHEME_NAME = /^[a-z][a-z0-9+.-]*$/;

/**
 * Schemes `REDIRECT_URI_CUSTOM_SCHEMES` may never name (#774): the ones a
 * browser or the operating system acts on itself, so an authorization response
 * sent to one would run script, read or write local data, open another
 * application with the code in its arguments, or stay inside the browser.
 * `http` and `https` are here too: they have rules of their own (loopback only
 * for `http`), and the list must not be a way around them.
 *
 * The authorization server refuses these at boot and again on every redirect
 * URI it judges, so a list that somehow holds one still widens nothing.
 */
export const REFUSED_CUSTOM_REDIRECT_URI_SCHEMES: ReadonlySet<string> = new Set([
  // Web schemes with rules of their own.
  'http',
  'https',
  'ws',
  'wss',
  'ftp',
  // Schemes a browser executes or resolves locally.
  'javascript',
  'vbscript',
  'data',
  'file',
  'blob',
  'about',
  'filesystem',
  'view-source',
  'jar',
  'resource',
  // Schemes the operating system hands to another application.
  'intent',
  'mailto',
  'tel',
  'sms',
  // Browser-internal schemes.
  'chrome',
  'chrome-extension',
  'chrome-untrusted',
  'devtools',
  'edge',
  'opera',
  'moz-extension',
  'safari-extension',
  'ms-browser-extension',
]);

/**
 * Parse `REDIRECT_URI_CUSTOM_SCHEMES` (#774): scheme names, separated by
 * spaces or commas, that a redirect URI may use besides `https`, loopback
 * `http` and an RFC 8252 §7.1 reverse-domain scheme. Names are lower-cased,
 * since a scheme is case-insensitive (RFC 3986 §3.1), and repeats are dropped.
 *
 * Refuses the boot, naming the variable and the entry, when an entry is not a
 * scheme name (a trailing colon included) or is one of
 * {@link REFUSED_CUSTOM_REDIRECT_URI_SCHEMES}.
 */
export function parseRedirectUriCustomSchemes(
  raw: string,
  ctx: z.RefinementCtx
): readonly string[] {
  const entries = [
    ...new Set(
      raw
        .split(/[\s,]+/)
        .map((entry) => entry.trim().toLowerCase())
        .filter((entry) => entry.length > 0)
    ),
  ];
  let valid = true;
  for (const entry of entries) {
    if (!URI_SCHEME_NAME.test(entry)) {
      ctx.addIssue({
        code: 'custom',
        message: `REDIRECT_URI_CUSTOM_SCHEMES entry "${entry}" is not a URI scheme name. Write the name alone, such as cursor: a letter, then letters, digits, "+", "-" or ".", with no colon.`,
      });
      valid = false;
    } else if (entry === 'http' || entry === 'https') {
      ctx.addIssue({
        code: 'custom',
        message: `REDIRECT_URI_CUSTOM_SCHEMES entry "${entry}" is not allowed: https redirect URIs are always accepted and http ones only to a loopback host, and the list is no way around that.`,
      });
      valid = false;
    } else if (REFUSED_CUSTOM_REDIRECT_URI_SCHEMES.has(entry)) {
      ctx.addIssue({
        code: 'custom',
        message: `REDIRECT_URI_CUSTOM_SCHEMES entry "${entry}" is not allowed: a browser or the operating system acts on ${entry}: URIs itself, so it must never receive an authorization response.`,
      });
      valid = false;
    }
  }
  return valid ? Object.freeze(entries) : z.NEVER;
}
