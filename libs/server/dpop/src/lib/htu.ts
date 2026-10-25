import { DpopProofError } from './dpop-error';

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

/** A `.` or `..` path segment, written plainly or percent-encoded. */
function isDotSegment(segment: string): boolean {
  const decoded = segment.replace(/%2e/gi, '.');
  return decoded === '.' || decoded === '..';
}

/**
 * Whether the path of an absolute URL is one a server routes as written: no
 * `.` or `..` segment, plain or percent-encoded, and no backslash.
 *
 * The URL parser resolves those, so `/a/../admin` would compare as `/admin`,
 * while a router serves it as written, for instance through `/a/:id/admin`. A
 * proof made for `/admin` must not pass there, so the verifier refuses such a
 * request URL rather than normalize it. Only the proof's `htu` is normalized.
 */
export function hasPlainPath(url: string): boolean {
  const schemeEnd = url.indexOf('://');
  if (schemeEnd === -1) return false;
  const rest = url.slice(schemeEnd + 3);
  if (rest.includes('\\')) return false;
  const pathStart = rest.indexOf('/');
  if (pathStart === -1) return true;
  const path = rest.slice(pathStart).split(/[?#]/, 1)[0];
  return !path.split('/').some(isDotSegment);
}

/**
 * The URL to check a proof against, from the server's own origin and the
 * request target as the request line gave it (Node's `request.url`).
 *
 * The target must be in origin form (RFC 9112 §3.2.1): a path that starts
 * with one `/`. A request line may instead carry an absolute URL, such as
 * `POST https://other.example/token HTTP/1.1`; Node passes it through as
 * `request.url` and a router still serves it by its path. Taking the scheme
 * and host from it would let the client choose what `htu` is compared with,
 * so such a target, and any other that is not origin form, is refused with
 * `htu`. The query and fragment are dropped.
 *
 * @param origin The server's own origin, from its configuration: the issuer
 *   or the realm's host, never the request's `Host` header.
 */
export function dpopRequestUrl(origin: string, target: string): string {
  let base: URL;
  try {
    base = new URL(origin);
  } catch {
    throw new TypeError('The origin to check DPoP proofs for must be an absolute http(s) URL');
  }
  if (base.protocol !== 'https:' && base.protocol !== 'http:') {
    throw new TypeError('The origin to check DPoP proofs for must be an absolute http(s) URL');
  }
  if (!target.startsWith('/') || target.startsWith('//')) throw new DpopProofError('htu');
  return `${base.origin}${target.split(/[?#]/, 1)[0]}`;
}
