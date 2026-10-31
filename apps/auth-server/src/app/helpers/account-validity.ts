/**
 * WHETHER AN ACCOUNT STILL ACCEPTS A CREDENTIAL IT WAS ISSUED (#748).
 *
 * A browser session, a refresh token, an authorization code and an access
 * token outlive the sign-in that issued them. Each place that accepts one asks
 * {@link accountCredentialRefusal} with the user row and the credential's issue
 * time, and refuses it on any answer but `null`:
 *
 * - `user_disabled`: the account is disabled now.
 * - `issued_before_disablement`: the account was disabled after the credential
 *   was issued, and has been enabled since. `users.not_valid_before` holds the
 *   time it was last disabled (migration 0044), and re-enabling never clears
 *   it, so a session or a token nobody used while the account was disabled
 *   stays refused: whoever held it signs in again.
 *
 * The issue times come from two clocks and at two precisions: a session's
 * `createdAt` and an access token's `iat` (whole seconds) are the auth
 * server's clock, a refresh token's and a code's `created_at` the database's,
 * rounded to the second, as `not_valid_before` is the database's to the
 * millisecond. So a credential issued up to {@link NOT_VALID_BEFORE_MARGIN_MS}
 * after the disablement counts as issued before it. That costs nothing: no
 * credential is issued to a disabled account, so only one issued within that
 * second after the account was enabled again is refused too.
 */

/** What these checks read of a `users` row. */
export interface AccountState {
  readonly enabled: boolean;
  /** When the account was last disabled, in epoch ms; `null` when it never was. */
  readonly notValidBefore: number | null;
}

/** Why an account no longer accepts a credential it was issued. */
export type AccountCredentialRefusal = 'user_disabled' | 'issued_before_disablement';

/**
 * How long after `not_valid_before`, in milliseconds, a credential may have
 * been issued and still count as issued before it. One second: the rounding
 * of a time kept to the second, and a small skew between the auth server's
 * clock and the database's.
 */
export const NOT_VALID_BEFORE_MARGIN_MS = 1000;

/**
 * Whether a credential issued at `issuedAtMs` (epoch ms) was issued before the
 * account was last disabled. A credential with no issue time counts as issued
 * before, once the account has been disabled.
 */
export function issuedBeforeDisablement(
  user: Pick<AccountState, 'notValidBefore'>,
  issuedAtMs: number | undefined
): boolean {
  const notValidBefore = user.notValidBefore;
  if (notValidBefore === null || notValidBefore === undefined) return false;
  if (issuedAtMs === undefined || !Number.isFinite(issuedAtMs)) return true;
  return issuedAtMs <= notValidBefore + NOT_VALID_BEFORE_MARGIN_MS;
}

/**
 * Why `user` refuses a credential it was issued at `issuedAtMs` (epoch ms), or
 * `null` when it accepts it. See the module comment.
 */
export function accountCredentialRefusal(
  user: AccountState,
  issuedAtMs: number | undefined
): AccountCredentialRefusal | null {
  if (!user.enabled) return 'user_disabled';
  if (issuedBeforeDisablement(user, issuedAtMs)) return 'issued_before_disablement';
  return null;
}

/**
 * An access token's issue time in epoch ms, from its `iat` claim (RFC 7519
 * §4.1.6, whole seconds); `undefined` when it carries none.
 */
export function accessTokenIssuedAt(claims: { readonly iat?: number }): number | undefined {
  return typeof claims.iat === 'number' && Number.isFinite(claims.iat)
    ? claims.iat * 1000
    : undefined;
}
