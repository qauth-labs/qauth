/**
 * THE LINKS OF THE ENGINE'S MAIL (PRO-14, #637; ADR-019 Decisions 1 and 6).
 *
 * Every link a mail carries points at the auth server of the realm the
 * account belongs to: the realm's issuer, read from the realm row, followed by
 * a fixed path. A link never starts at a URL from the request, the brand
 * settings or `EMAIL_BASE_URL`, and never at `/ui/*`: opening one starts an
 * interaction in that browser, with its own flow cookie, as the authorization
 * endpoint does.
 */

/** The auth-server path a mailed pass link opens. */
export const MAIL_PASS_PATH = '/auth/pass';

/** The query parameter that carries the pass. Censored in every logged URL. */
export const MAIL_PASS_PARAMETER = 'pass';

/** A pass: 32 CSPRNG bytes, base64url without padding (43 characters, 256 bits). */
export const MAIL_PASS_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** Whether `value` has the shape of a pass. */
export function isMailPass(value: unknown): value is string {
  return typeof value === 'string' && MAIL_PASS_PATTERN.test(value);
}

/**
 * Whether `baseUrl` is a realm issuer a link may start at: an absolute
 * `https` (or, on a development stack, `http`) URL with no credentials, query,
 * fragment or trailing slash. The realm row stores its issuer in that form.
 */
export function isMailBaseUrl(baseUrl: string): boolean {
  if (baseUrl.endsWith('/')) return false;
  let url: URL;
  try {
    url = new URL(baseUrl);
  } catch {
    return false;
  }
  return (
    (url.protocol === 'https:' || url.protocol === 'http:') &&
    url.username === '' &&
    url.password === '' &&
    url.search === '' &&
    url.hash === '' &&
    !baseUrl.includes('?') &&
    !baseUrl.includes('#')
  );
}

/**
 * The absolute URL of `path` on the realm's auth server: the issuer followed
 * by `path`, joined as strings so a path the issuer carries is kept.
 *
 * @throws Error when `baseUrl` is not a realm issuer or `path` does not start
 *   with a single `/`
 */
export function mailLink(baseUrl: string, path: string): string {
  if (!isMailBaseUrl(baseUrl)) throw new Error('a mail link starts at the realm issuer');
  if (!path.startsWith('/') || path.startsWith('//')) {
    throw new Error(`a mail link path must start with a single "/": ${JSON.stringify(path)}`);
  }
  return `${baseUrl}${path}`;
}

/**
 * The link a mailed pass opens: `<issuer>/auth/pass?pass=<pass>`. The pass is
 * base64url, so it needs no escaping.
 *
 * @throws Error when `pass` is not a pass, or as {@link mailLink}
 */
export function mailPassUrl(baseUrl: string, pass: string): string {
  if (!isMailPass(pass)) throw new Error('a mailed pass is 43 base64url characters');
  return mailLink(baseUrl, `${MAIL_PASS_PATH}?${MAIL_PASS_PARAMETER}=${pass}`);
}
