import { isNativeAppRedirectUri } from './oauth-redirect';

/**
 * The lifetime of a refresh-token family under its realm's `sso_max_lifespan`
 * (ADR-019 Decision 3, issue #552).
 *
 * A family is every refresh token descended from one code exchange or sign-in.
 * Each rotation gives the new token the realm's refresh lifetime
 * (`tokens.refreshTokenLifespanSeconds`, #527) from now, so
 * without a limit a client that keeps refreshing keeps the family alive for
 * ever. When the realm sets `sso_max_lifespan`, the family ends that many
 * seconds after its start (`refresh_tokens.family_created_at`), and no token of
 * it expires later than that. A realm that sets none keeps the sliding expiry.
 *
 * The family also ends no later than the browser session that started it
 * (`refresh_tokens.family_session_expires_at`, the authorization code's
 * session end), so no token outlives the SSO session that granted it, as with
 * an SSO session maximum: a silent re-authorization just before the session's
 * end starts a family that ends with the session. A family no browser session
 * started (`/auth/login`, the legacy Bearer path #524 retired) has only its start plus the
 * limit. Both caps apply only when the realm sets `sso_max_lifespan`.
 *
 * The limit is read from the request's realm row at each use (the realm
 * resolver's, at most its cache time old), never stored on the token, so a
 * realm that lowers it ends its older families at their next use.
 *
 * A browser-based client's family never slides, whatever the realm sets
 * (RFC 10017 §6.3.2.3, OAuth 2.1 -17 §9.3.2; ADR-019 Decision 3, #928): a
 * rotated token expires no later than the token it replaces, so no token of
 * the family expires after the family's first token. The family lasts the
 * refresh lifetime from its start at most, and the realm's limit, when it is
 * shorter, ends it sooner. Confidential clients and native apps keep the
 * sliding expiry.
 */

/**
 * Whether a client is a browser-based application for its refresh tokens
 * (RFC 10017, OAuth 2.0 for Browser-Based Applications; #928): a public client
 * (`token_endpoint_auth_method` `none`, RFC 6749 §2.1) with a redirect URI
 * that is not a native app's ({@link isNativeAppRedirectUri}), in practice an
 * `https` one. A public client that has one is browser-based even when it also
 * has native ones, and so is a public client that has none: only a client whose
 * every redirect URI is a native app's is a native app. A native app that calls
 * back on a claimed `https` URI (RFC 8252 §7.2) is treated as browser-based
 * too, since no server can tell that URI from a web page's.
 *
 * Read from the client's registration at each refresh, as the rest of the
 * refresh grant reads it. A client whose `tokenEndpointAuthMethod` is absent
 * is confidential, as the token endpoint treats it.
 *
 * @param client - the client presenting the refresh token
 */
export function isBrowserBasedClient(client: {
  readonly tokenEndpointAuthMethod?: string;
  readonly redirectUris?: readonly string[];
}): boolean {
  if (client.tokenEndpointAuthMethod !== 'none') return false;
  const redirectUris = client.redirectUris ?? [];
  return redirectUris.length === 0 || !redirectUris.every(isNativeAppRedirectUri);
}

/**
 * When a family ends, in epoch milliseconds: the earlier of its start plus the
 * realm's `sso_max_lifespan` and the end of the browser session that started
 * it, or `null` when the realm sets no `sso_max_lifespan`.
 *
 * The realm refuses a limit of zero or less (`realms_sso_max_lifespan_positive`).
 *
 * @param familyCreatedAt - the family's start, in epoch milliseconds
 * @param ssoMaxLifespanSeconds - the realm's `sso_max_lifespan`
 * @param familySessionExpiresAt - the absolute end of the browser session that
 *   started the family, in epoch milliseconds; `null` when none did
 */
export function refreshFamilyEnd(
  familyCreatedAt: number,
  ssoMaxLifespanSeconds: number | null,
  familySessionExpiresAt: number | null
): number | null {
  if (ssoMaxLifespanSeconds === null) return null;
  const byLimit = familyCreatedAt + ssoMaxLifespanSeconds * 1000;
  return familySessionExpiresAt === null ? byLimit : Math.min(byLimit, familySessionExpiresAt);
}

/**
 * The expiry of a refresh token issued at `now`: the refresh lifespan from
 * `now`, but never later than the end of its family.
 *
 * @param now - when the token is issued, in epoch milliseconds
 * @param lifespanSeconds - the realm's refresh lifetime (`tokenLifetimesOf`, #527)
 * @param familyEnd - from {@link refreshFamilyEnd}
 */
export function refreshTokenExpiresAt(
  now: number,
  lifespanSeconds: number,
  familyEnd: number | null
): number {
  const sliding = now + lifespanSeconds * 1000;
  return familyEnd === null ? sliding : Math.min(sliding, familyEnd);
}

/**
 * The expiry of the refresh token a rotation issues at `now` in place of the
 * presented one: {@link refreshTokenExpiresAt}, and for a browser-based client
 * ({@link isBrowserBasedClient}) never later than the token it replaces
 * (RFC 10017 §6.3.2.3, #928). Every rotation of such a family applies it, so
 * no token of the family expires after its first token: the family's first
 * expiry is carried down the chain, and a realm that raises its refresh
 * lifetime later does not lengthen it. A realm that lowers the lifetime or the
 * family's end shortens it further. The presented token is live when this
 * runs, so the new token is never issued expired.
 *
 * @param now - when the token is issued, in epoch milliseconds
 * @param lifespanSeconds - the realm's refresh lifetime (`tokenLifetimesOf`, #527)
 * @param familyEnd - from {@link refreshFamilyEnd}
 * @param replacedExpiresAt - the presented token's expiry, in epoch milliseconds
 * @param browserBased - from {@link isBrowserBasedClient}
 */
export function rotatedRefreshTokenExpiresAt(
  now: number,
  lifespanSeconds: number,
  familyEnd: number | null,
  replacedExpiresAt: number,
  browserBased: boolean
): number {
  const expiresAt = refreshTokenExpiresAt(now, lifespanSeconds, familyEnd);
  return browserBased ? Math.min(expiresAt, replacedExpiresAt) : expiresAt;
}

/**
 * Whether a family has ended at `now`. Its end is the first moment it is no
 * longer live, as a token's `expires_at` is.
 *
 * @param familyEnd - from {@link refreshFamilyEnd}
 */
export function refreshFamilyEnded(familyEnd: number | null, now: number): boolean {
  return familyEnd !== null && now >= familyEnd;
}
