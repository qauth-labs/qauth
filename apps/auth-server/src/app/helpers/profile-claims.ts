/**
 * OIDC `profile`-scope claim release (OIDC Core §5.4, issue #755).
 *
 * The ID token and the userinfo response release the same profile claims for
 * the same grant, so both call {@link resolveProfileClaimsForScopes}: the
 * authorization_code grant (the only grant that signs an ID token) with the
 * code's scopes, and userinfo with the access token's `scope`. Before #755 the
 * ID token carried `name` whatever was granted, while userinfo already
 * required `profile`.
 *
 * QAuth asserts one profile claim today, `name`. A profile claim added later
 * goes here, so both release points pick it up together.
 *
 * Access tokens carry no profile claim under any scope.
 */
export type ProfileClaims = { name: string } | Record<string, never>;

/** The OIDC scope that releases the profile claims (OIDC Core §5.4). */
export const PROFILE_SCOPE = 'profile';

/** The stored user fields the profile claims derive from. */
export interface ProfileClaimSource {
  readonly firstName?: string | null;
  readonly lastName?: string | null;
}

/**
 * The OIDC `name` claim (OIDC Core §5.1): the end-user's full display name.
 *
 * QAuth stores `firstName` / `lastName` separately (both optional), so the
 * non-blank parts are joined with a space. Returns `undefined` when neither is
 * set, so the claim is omitted rather than emitted as an empty string.
 */
export function resolveDisplayName(user: ProfileClaimSource): string | undefined {
  const parts = [user.firstName, user.lastName].filter(
    (part): part is string => typeof part === 'string' && part.trim().length > 0
  );
  return parts.length > 0 ? parts.join(' ') : undefined;
}

/**
 * The profile claims a token or response with `grantedScopes` may carry:
 * `name` when `profile` was granted and the user has a name stored, nothing
 * otherwise.
 *
 * An unavailable claim is absent from the result, never present as
 * `undefined`, so spreading the result adds no key (OIDC Core §5.3.2 permits
 * omitting unavailable claims).
 */
export function resolveProfileClaimsForScopes(
  user: ProfileClaimSource,
  grantedScopes: Iterable<string>
): ProfileClaims {
  for (const scope of grantedScopes) {
    if (scope === PROFILE_SCOPE) {
      const name = resolveDisplayName(user);
      return name === undefined ? {} : { name };
    }
  }
  return {};
}
