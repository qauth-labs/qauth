import type { EnvironmentPolicy } from './environment-policy';

/**
 * Host literals treated as loopback/localhost for the plain-HTTP redirect gate
 * (ADR-008 §5, #197). IPv6 `::1` is matched after stripping URL brackets; the
 * full IPv4 `127.0.0.0/8` block is matched by {@link isIpv4LoopbackHost}.
 */
const LOOPBACK_HOSTS = new Set(['localhost', '::1']);

/** True when `host` is anywhere in the IPv4 loopback block `127.0.0.0/8`. */
function isIpv4LoopbackHost(host: string): boolean {
  const octets = host.split('.');
  if (octets.length !== 4) return false;
  for (const o of octets) {
    if (!/^\d{1,3}$/.test(o)) return false;
    const n = Number(o);
    if (n < 0 || n > 255) return false;
  }
  return Number(octets[0]) === 127;
}

/**
 * True when `redirectUri` is an `http://` (NOT https) loopback/localhost URI —
 * the exact shape ADR-008 §5 permits only for `development`. An https URI (even
 * to localhost) is fine in every environment and returns false; a non-loopback
 * `http://` URI also returns false here (it is rejected outright by the policy
 * gate, never "allowed in development"). Unparseable input returns false so the
 * caller's existing exact-match / scheme checks remain authoritative.
 */
export function isHttpLocalhostRedirect(redirectUri: string): boolean {
  let url: URL;
  try {
    url = new URL(redirectUri);
  } catch {
    return false;
  }
  if (url.protocol !== 'http:') return false;
  const host = url.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  return LOOPBACK_HOSTS.has(host) || isIpv4LoopbackHost(host);
}

/**
 * Whether a (already registered, exact-matched) `redirect_uri` is permitted
 * under the effective environment policy (ADR-008 §5, #197).
 *
 * The ONLY environment-gated case is an `http://localhost` (loopback) redirect:
 * permitted for a `development` client (`localhostRedirectAllowed`), rejected as
 * https-only for `staging`/`production`. Everything else — any https URI, any
 * custom-scheme native redirect — is unaffected and returns true; this gate
 * never widens what is allowed, it only withholds the plain-HTTP-loopback
 * convenience outside development.
 *
 * FAIL-SAFE: an unset client/realm resolves to the `production` profile, whose
 * `localhostRedirectAllowed` is false, so a misconfigured deployment rejects
 * plain-HTTP loopback redirects (the hardened direction).
 *
 * NB: this is a SECOND gate, layered after the existing exact-match check
 * (`client.redirectUris.includes(redirect_uri)`) — it does not replace it. A
 * URI must be both registered AND allowed by the environment.
 */
export function isRedirectUriAllowedForPolicy(
  redirectUri: string,
  policy: EnvironmentPolicy
): boolean {
  if (!isHttpLocalhostRedirect(redirectUri)) return true;
  return policy.localhostRedirectAllowed;
}

/**
 * Build redirect URL for authorize success or error (RFC 6749 4.1.2, 4.1.2.1).
 * redirect_uri is exact; we append ?key=value&...
 * Fragment is stripped (OAuth 2.1).
 */
export function buildRedirectUrl(
  redirectUri: string,
  params:
    | { code: string; state?: string }
    | { error: string; error_description?: string; state?: string }
): string {
  const u = new URL(redirectUri);
  u.hash = '';
  for (const [k, v] of Object.entries(params)) {
    if (v != null && v !== '') u.searchParams.set(k, v);
  }
  return u.toString();
}
