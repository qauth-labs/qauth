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
 * The ONLY environment-gated case is an `http://localhost` (loopback) redirect.
 * It is permitted when EITHER the environment opts in
 * (`localhostRedirectAllowed`, i.e. `development`) OR PKCE is enforced
 * (`pkceRequired`, i.e. `staging`/`production`). Loopback redirects are the
 * RFC 8252 standard for native / CLI clients — including every discover-then-
 * register MCP client — and the traffic never leaves the device; PKCE (S256)
 * is precisely what backstops loopback authorization-code interception on a
 * shared host. So loopback + PKCE is safe in any environment, and gating it
 * on PKCE (rather than https-only) is what lets native clients complete the
 * auth-code flow against a production AS. Everything else — any https URI, any
 * custom-scheme native redirect — is unaffected and returns true; this gate
 * never widens what is allowed.
 *
 * FAIL-SAFE: a future non-`development` profile that ALSO drops `pkceRequired`
 * would once again reject plain-HTTP loopback (no PKCE → interceptable), the
 * hardened direction. An unset client/realm still resolves to `production`,
 * which requires PKCE and therefore now permits loopback + PKCE.
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
  return policy.localhostRedirectAllowed || policy.pkceRequired;
}

/**
 * Parameters of an authorization response (RFC 6749 §4.1.2 success, §4.1.2.1
 * error), plus the RFC 9207 issuer identifier.
 *
 * `iss` is REQUIRED on both branches by construction (#282). RFC 9207 §2 says
 * the AS "MUST" identify itself in every authorization response — success and
 * error alike — because a mix-up attacker's whole play is to get a client to
 * deliver a code (or an error it reacts to) from the WRONG AS. Making the
 * field part of the union rather than an optional add-on means TypeScript
 * rejects a call site that forgets it: omission is a compile error, not a
 * silently-downgraded security property.
 */
export type AuthorizationResponseParams = (
  | { code: string; state?: string }
  | { error: string; error_description?: string; state?: string }
) & {
  /**
   * The AS issuer identifier, VERBATIM as advertised in the `issuer` member of
   * the discovery metadata. Callers MUST source it from
   * `resolveIssuerIdentifier(fastify.jwtUtils.getIssuer())` so the two can
   * never drift.
   */
  iss: string;
};

/**
 * Build redirect URL for authorize success or error (RFC 6749 4.1.2, 4.1.2.1).
 * redirect_uri is exact; we append ?key=value&...
 * Fragment is stripped (OAuth 2.1).
 *
 * RFC 9207 §2 (#282): `iss` is always appended. It is set explicitly rather
 * than through the generic parameter loop below, which drops empty values —
 * an empty issuer must surface as a visibly broken response, never as a
 * silently absent mix-up defence.
 *
 * VERBATIM EMISSION: the issuer string is never parsed as a URL here. Feeding
 * it through `new URL(...)` would normalise it (case folding of the authority,
 * default-port elision, path/percent-encoding rewrites), and RFC 9207 §2.4
 * requires clients to compare `iss` to their configured issuer by simple string
 * comparison (RFC 3986 §6.2.1) with no normalisation — so any rewrite here
 * turns a legitimate response into a rejected one. Passing it as a
 * `searchParams` value only applies transport-level percent-encoding, which the
 * client reverses before comparing.
 */
export function buildRedirectUrl(redirectUri: string, params: AuthorizationResponseParams): string {
  const u = new URL(redirectUri);
  u.hash = '';
  const { iss, ...responseParams } = params;
  for (const [k, v] of Object.entries(responseParams)) {
    if (v != null && v !== '') u.searchParams.set(k, v);
  }
  u.searchParams.set('iss', iss);
  return u.toString();
}
