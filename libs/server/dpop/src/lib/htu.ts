/** A percent-encoded octet. */
const PERCENT_ENCODED = /%([0-9A-Fa-f]{2})/g;

/** RFC 3986 §2.3 unreserved characters, which never need percent-encoding. */
const UNRESERVED = /^[A-Za-z0-9\-._~]$/;

/**
 * The comparable form of an HTTP URI for the `htu` check (RFC 9449 §4.3
 * step 9), or `undefined` when it is not an absolute `http` or `https` URI.
 *
 * Query and fragment are dropped, as the check requires. Syntax-based and
 * scheme-based normalization (RFC 3986 §6.2.2 and §6.2.3, which RFC 9449
 * §4.3 recommends) come from the WHATWG URL parser: lower-case scheme and
 * host, no default port, dot segments resolved, an empty path as `/`. On top
 * of it, a percent-encoded unreserved character is decoded and every other
 * percent-encoding is written in upper case (§6.2.2.1, §6.2.2.2). A URI with
 * user information is refused: RFC 9110 §4.2.4 treats it as an error in an
 * `http` or `https` URI.
 */
export function normalizeHtu(value: string): string | undefined {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return undefined;
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined;
  if (url.username !== '' || url.password !== '') return undefined;

  const path = url.pathname.replace(PERCENT_ENCODED, (_match, hex: string) => {
    const character = String.fromCharCode(Number.parseInt(hex, 16));
    return UNRESERVED.test(character) ? character : `%${hex.toUpperCase()}`;
  });
  return `${url.protocol}//${url.host}${path}`;
}
