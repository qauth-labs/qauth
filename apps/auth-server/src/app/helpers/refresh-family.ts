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
 * The limit is read from the realm at each use, never stored on the token, so
 * a realm that lowers it ends its older families at their next use.
 */

/**
 * When a family ends, in epoch milliseconds: its start plus the realm's
 * `sso_max_lifespan`, or `null` when the realm sets none.
 *
 * A limit of zero or less ends the family at its start, as it ends a browser
 * session at its creation.
 *
 * @param familyCreatedAt - the family's start, in epoch milliseconds
 * @param ssoMaxLifespanSeconds - the realm's `sso_max_lifespan`
 */
export function refreshFamilyEnd(
  familyCreatedAt: number,
  ssoMaxLifespanSeconds: number | null
): number | null {
  return ssoMaxLifespanSeconds === null ? null : familyCreatedAt + ssoMaxLifespanSeconds * 1000;
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
