/**
 * The lifetime of a refresh-token family under its realm's `sso_max_lifespan`
 * (ADR-019 Decision 3, issue #552).
 *
 * A family is every refresh token descended from one code exchange or sign-in.
 * Each rotation gives the new token `REFRESH_TOKEN_LIFESPAN` from now, so
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
 */

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
 * @param lifespanSeconds - `REFRESH_TOKEN_LIFESPAN`
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
 * Whether a family has ended at `now`. Its end is the first moment it is no
 * longer live, as a token's `expires_at` is.
 *
 * @param familyEnd - from {@link refreshFamilyEnd}
 */
export function refreshFamilyEnded(familyEnd: number | null, now: number): boolean {
  return familyEnd !== null && now >= familyEnd;
}
