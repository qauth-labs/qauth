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
  /** RFC 8707 resource → the scopes approved for it (`oauth_consents.resource_scopes`). */
  resourceScopes: Record<string, string[]>;
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
 * True iff the stored grant covers `scopes` at every one of `resources` (RFC
 * 8707). A `resource` becomes the token's `aud`, any absolute URI is accepted,
 * and nothing else on the authorization-code flow limits it, so the consent
 * screen is where it is decided: the grant records the approved scopes per
 * resource, and an approval for one resource server says nothing about
 * another.
 *
 * Without a `resource` the `aud` is not the client's to choose (the operator-
 * configured audience, else the client_id) and the scopes alone decide.
 */
export function consentCovers(
  consent: OAuthConsentLike,
  scopes: string[],
  resources: readonly string[]
): boolean {
  if (!isScopeSubset(scopes, consent.scopes)) return false;
  // `hasOwn` first: an empty scope set is a subset of anything, and must
  // still not be served for a resource the user never saw.
  return resources.every(
    (resource) =>
      Object.hasOwn(consent.resourceScopes, resource) &&
      isScopeSubset(scopes, consent.resourceScopes[resource])
  );
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
 * the existing consent row and the scopes and RFC 8707 resources being
 * requested now.
 *
 * Returns false when:
 *   - no active consent row exists
 *   - the requested scopes are not a subset of the granted ones
 *   - the scopes were not granted for every requested resource
 *     (see {@link consentCovers})
 *   - the client is a dynamic-registered client and still inside the
 *     `DYNAMIC_CLIENT_BADGE_DAYS` window (we force re-consent to give the
 *     user another chance to notice the "Newly registered" warning per
 *     issue #150 phishing-defense requirements)
 */
export function canSkipConsent(
  consent: OAuthConsentLike | undefined,
  client: OAuthClientLike,
  requestedScopes: string[],
  requestedResources: readonly string[]
): boolean {
  if (!consent) return false;
  if (consent.revokedAt !== null) return false;
  if (isDynamicClientWithinBadgeWindow(client)) return false;
  return consentCovers(consent, requestedScopes, requestedResources);
}

/**
 * True when the client was dynamic-registered recently enough to warrant
 * the phishing-defense badge. Defaults to `false` for null
 * `dynamicRegisteredAt` — first-party / hand-provisioned clients are
 * never flagged as new.
 */
export function isDynamicClientWithinBadgeWindow(
  client: Pick<OAuthClientLike, 'dynamicRegisteredAt'>
): boolean {
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
 * Extract the host (with its port) of a redirect URI, for the issuer page an
 * authorization error is shown on instead of a redirect
 * (`helpers/authorization-error.ts`), so the user sees where the link goes.
 * Returns the raw value if it can't be parsed (so the page still shows
 * *something* rather than hiding it). The consent screen does not use it: it
 * shows where the code goes from `clientDisplay` (`helpers/client-display.ts`,
 * #593), which also tells a loopback redirect apart as "this device".
 */
export function redirectHost(redirectUri: string): string {
  try {
    return new URL(redirectUri).host || redirectUri;
  } catch {
    return redirectUri;
  }
}
