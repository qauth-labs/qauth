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
 * Lexical shape of a loopback redirect URI: `http://` + loopback host literal
 * + optional port + the rest. The host MUST be followed by `:`, `/`, `?` or
 * the end of the string, so userinfo (`http://127.0.0.1@evil.example/`),
 * backslash tricks and host suffixes (`http://localhost.evil.example/`) never
 * match. Groups: 1 = host, 2 = port digits (absent when portless), 3 = rest.
 */
const LOOPBACK_REDIRECT_SHAPE =
  /^http:\/\/(\[::1\]|localhost|127(?:\.\d{1,3}){3})(?::(\d{1,5}))?([/?#].*)?$/;

/**
 * Split a loopback redirect URI into its port-free form and its port, or
 * return null when `uri` is not a loopback redirect. Purely lexical — see
 * {@link redirectUriMatchesRegistered} for why no URI parser is involved.
 */
function splitLoopbackRedirect(uri: string): { withoutPort: string; port?: string } | null {
  const m = LOOPBACK_REDIRECT_SHAPE.exec(uri);
  if (!m) return null;
  const [, host, port, rest = ''] = m;
  if (host.startsWith('127.') && !isIpv4LoopbackHost(host)) return null;
  if (port !== undefined) {
    // RFC 3986 allows leading zeros, but a canonical 1–65535 port is the only
    // shape a real listener hands back; anything else is refused outright.
    if (!/^[1-9]\d*$/.test(port) || Number(port) > 65535) return null;
  }
  return { withoutPort: `http://${host}${rest}`, port };
}

/**
 * Whether the `redirect_uri` of an authorization request matches one
 * registered for the client (the pre-registered set, the DCR set, or a CIMD
 * document's `redirect_uris`).
 *
 * Exact string comparison (RFC 9700 §2.1, OAuth 2.1 §2.3.1), with the ONE
 * exception both specs carve out: loopback redirects of native apps may carry
 * any port. RFC 8252 §7.3 — the AS "MUST allow any port to be specified at the
 * time of the request for loopback IP redirect URIs", because the OS hands the
 * client an ephemeral port only when it opens its listener. So when BOTH the
 * requested and the registered URI are loopback redirects, they match if they
 * are byte-identical once the port (`:NNNN`, if any) is removed from each.
 * Scheme, host literal, path, query — everything else — must still be exactly
 * equal; there are no wildcards and no prefix matching.
 *
 * - Loopback means the `http` scheme and a host of `127.0.0.0/8` (dotted
 *   decimal), `[::1]`, or `localhost`. `https`, custom schemes and every other
 *   host keep exact matching, port included.
 * - `localhost` IS included. RFC 8252 §8.3 calls it NOT RECOMMENDED (a client
 *   should listen on the IP literal so a resolver or firewall cannot redirect
 *   the name), but RFC 9700 §2.1 names "localhost redirection URIs" in the port
 *   exception, and real native MCP clients register it — Claude Code's CIMD
 *   document declares `http://localhost/callback` and calls back on
 *   `http://localhost:<ephemeral>/callback`. The name is never resolved here;
 *   the exception only lets the port vary, and the browser is what connects.
 *   The literal hosts are never interchangeable: `localhost` does not match
 *   `127.0.0.1`, nor `127.0.0.1` `[::1]`.
 * - The comparison is lexical — no URI parser takes part in the decision
 *   (see the SECURITY INVARIANT in `main.ts`). A parser would normalise case,
 *   percent-encoding, dot segments and default ports, and any divergence
 *   between the parser used here and the one the client or browser uses is a
 *   redirect-confusion bug. Stripping a strictly-shaped `:digits` after a
 *   literal host from both sides and comparing the rest byte-for-byte keeps
 *   the old exact-match guarantee for every other character.
 * - PKCE (S256), mandatory for every client, is what protects a loopback
 *   redirect on a shared host from a local listener on another port
 *   (RFC 8252 §8.1).
 *
 * The caller MUST redirect to the REQUESTED URI (it carries the port the
 * client is listening on) and store it on the authorization code; the token
 * endpoint then compares the token request's `redirect_uri` with the stored
 * value by exact string, port included (RFC 6749 §4.1.3) — this helper is not
 * used there.
 */
export function redirectUriMatchesRegistered(
  requested: string,
  registered: readonly string[]
): boolean {
  if (registered.includes(requested)) return true;
  const req = splitLoopbackRedirect(requested);
  if (!req) return false;
  return registered.some((r) => splitLoopbackRedirect(r)?.withoutPort === req.withoutPort);
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
 * NB: this is a SECOND gate, layered after the registered-set check
 * ({@link redirectUriMatchesRegistered}) — it does not replace it. A URI must
 * be both registered AND allowed by the environment. The two agree by
 * construction: every URI that matches only through the loopback-port
 * exception is an `http://` loopback URI, so it always reaches this gate.
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
  { code: string; state?: string } | { error: string; error_description?: string; state?: string }
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
