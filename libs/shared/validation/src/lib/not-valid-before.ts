/**
 * The margin of `users.not_valid_before` (#748): when the account was last
 * disabled, before which every browser session and token of the user stays
 * refused, also after the account is enabled again.
 *
 * The auth server's checks (`account-validity.ts`) and the database's SSF
 * relation of a user to a receiver both draw the line at this margin, so a
 * refresh token the token endpoint refuses relates the user to no receiver.
 */

/**
 * How long after `not_valid_before`, in milliseconds, a credential may have
 * been issued and still count as issued before it. One second: the rounding
 * of a time kept to the second, and a small skew between the auth server's
 * clock and the database's.
 */
export const NOT_VALID_BEFORE_MARGIN_MS = 1000;
