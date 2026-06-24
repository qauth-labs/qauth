import { env } from '../../config/env';

/**
 * Minimal view of an oauth_clients row consumed by the consent-screen
 * helpers. Kept local to avoid an `@nx/enforce-module-boundaries`
 * violation (`scope:app` → `scope:infra`) — the full types still live in
 * `@qauth-labs/infra-db` and repositories return them directly.
 */
export interface OAuthClientLike {
  scopes: string[];
  dynamicRegisteredAt: number | null;
}

/**
 * Minimal view of an oauth_consents row consumed by the consent-screen
 * helpers. See {@link OAuthClientLike} for the rationale.
 */
export interface OAuthConsentLike {
  scopes: string[];
  revokedAt: number | null;
}

/**
 * True iff every `requested` scope is already present in `granted`. Empty
 * `requested` is trivially covered — the authorization request itself
 * carried no scope, so there is nothing to consent to.
 *
 * Callers use this on the /oauth/authorize GET path to decide whether the
 * consent screen can be skipped for a previously-granted (user, client).
 */
export function isScopeSubset(requested: string[], granted: string[]): boolean {
  if (requested.length === 0) return true;
  const set = new Set(granted);
  for (const s of requested) {
    if (!set.has(s)) return false;
  }
  return true;
}

/**
 * Intersect the client's configured scope allowlist with what the request
 * asks for, preserving the request order and de-duplicating.
 *
 * Matches `authorize.ts`'s existing deny-by-default behaviour: a scope that
 * the client has not been provisioned for is silently dropped instead of
 * being granted.
 */
export function filterRequestedScopes(
  requestedRaw: string | undefined,
  client: OAuthClientLike
): string[] {
  const requested = (requestedRaw ?? '').split(/\s+/).filter((s) => s.length > 0);
  const allow = new Set(client.scopes);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const s of requested) {
    if (!allow.has(s)) continue;
    if (seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
}

/**
 * Whether the consent screen can be skipped for this (user, client) given
 * the existing consent row and the scopes being requested now.
 *
 * Returns false when:
 *   - no active consent row exists
 *   - the requested scopes are not a subset of the granted ones
 *   - the client is a dynamic-registered client and still inside the
 *     `DYNAMIC_CLIENT_BADGE_DAYS` window (we force re-consent to give the
 *     user another chance to notice the "Newly registered" warning per
 *     issue #150 phishing-defense requirements)
 */
export function canSkipConsent(
  consent: OAuthConsentLike | undefined,
  client: OAuthClientLike,
  requestedScopes: string[]
): boolean {
  if (!consent) return false;
  if (consent.revokedAt !== null) return false;
  if (isDynamicClientWithinBadgeWindow(client)) return false;
  return isScopeSubset(requestedScopes, consent.scopes);
}

/**
 * True when the client was dynamic-registered recently enough to warrant
 * the phishing-defense badge. Defaults to `false` for null
 * `dynamicRegisteredAt` — first-party / hand-provisioned clients are
 * never flagged as new.
 */
export function isDynamicClientWithinBadgeWindow(client: OAuthClientLike): boolean {
  if (!client.dynamicRegisteredAt) return false;
  if (env.DYNAMIC_CLIENT_BADGE_DAYS <= 0) return false;
  const ageMs = Date.now() - client.dynamicRegisteredAt;
  const windowMs = env.DYNAMIC_CLIENT_BADGE_DAYS * 24 * 60 * 60 * 1000;
  return ageMs < windowMs;
}

/**
 * Human-readable description for a scope string. Fallback is the raw
 * scope — that's intentionally legible because our scope naming
 * convention (`read:foo`, `write:foo`) is already close to plain English.
 */
const SCOPE_DESCRIPTIONS: Record<string, string> = {
  openid: 'Verify your identity',
  profile: 'View your basic profile information',
  email: 'View your email address',
  offline_access: 'Keep you signed in when you are not using the app',
};

export function describeScope(scope: string): string {
  return SCOPE_DESCRIPTIONS[scope] ?? scope;
}

/**
 * Non-IPv4 loopback host literals, matched after stripping any IPv6 brackets
 * (Node's `URL.hostname` returns `[::1]` *with* brackets). The full IPv4
 * `127.0.0.0/8` range is matched separately — see below.
 */
const LOOPBACK_HOSTS = new Set(['::1', 'localhost']);

/**
 * True when `host` is anywhere in the IPv4 loopback block `127.0.0.0/8`
 * (RFC 1122 §3.2.1.3). The whole /8 — not just `127.0.0.1` — loops back, so
 * `127.0.0.2`, `127.1.2.3`, etc. must all be treated as loopback; matching
 * only `127.0.0.1` let a malicious client dodge the consent-screen warning.
 */
function isIpv4Loopback(host: string): boolean {
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
 * Extract the hostname of a redirect_uri for display at the consent screen.
 * CIMD §6 calls out localhost-redirect impersonation: a malicious client can
 * present a `client_id` document whose redirect_uri points at the user's own
 * machine to intercept the code. Surfacing the destination host lets the
 * user notice an unexpected target. Returns the raw value if it can't be
 * parsed (so the screen still shows *something* rather than hiding it).
 */
export function redirectHost(redirectUri: string): string {
  try {
    return new URL(redirectUri).host || redirectUri;
  } catch {
    return redirectUri;
  }
}

/**
 * True when the redirect_uri targets a loopback / localhost address. The
 * consent screen warns on these because, for a client the AS never
 * pre-registered (CIMD), a localhost redirect means the authorization code
 * is delivered to whatever is listening on the user's own machine — a known
 * impersonation vector (CIMD §6, "localhost-redirect impersonation").
 */
export function isLoopbackRedirect(redirectUri: string): boolean {
  try {
    // URL.hostname keeps the brackets on IPv6 literals (`[::1]`); strip them
    // so both bracketed and bare forms match.
    const host = new URL(redirectUri).hostname.toLowerCase().replace(/^\[|\]$/g, '');
    return LOOPBACK_HOSTS.has(host) || isIpv4Loopback(host);
  } catch {
    return false;
  }
}
