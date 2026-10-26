import { InvalidRequestError, JWTInvalidError } from '@qauth-labs/shared-errors';

/**
 * THE REFUSAL OF A TOKEN WHOSE SUBJECT IS NOT AN ACTIVE USER (#513).
 *
 * A token outlives the sign-in that minted it, and its subject may stop being
 * a user it can act for: the account was deleted, or disabled, or the token
 * names no user at all (a `client_credentials` token's `sub` is its client).
 * Every route that refuses such a token raises it through one of the two
 * helpers below, so each answers one code and one wording wherever it is met:
 *
 * - {@link inactiveSubjectError} for an access token presented as a
 *   credential: `invalid_token` at an OAuth resource such as userinfo (RFC
 *   6750 §3.1), `invalid_access_token` on a problem route such as the management API;
 * - {@link inactiveSubjectTokenError} for a `subject_token` in a token
 *   exchange: `invalid_request`, as RFC 8693 §2.2.2 requires for a subject
 *   token that is not valid.
 *
 * The wording says no more than the code: not whether the account was deleted
 * or disabled, nor whether it ever was one. Which of these it was goes to the
 * event's `reason` and the operator's log, never to the wire.
 */

/** What a caller is told about an access token whose subject is not an active user. */
export const INACTIVE_SUBJECT_DESCRIPTION = 'Access token subject is not an active user';

/** What a caller is told about a `subject_token` whose subject is not an active user. */
export const INACTIVE_SUBJECT_TOKEN_DESCRIPTION = 'subject_token subject is not an active user';

/** The refusal of an access token whose subject is not an active user. */
export function inactiveSubjectError(): JWTInvalidError {
  return new JWTInvalidError(INACTIVE_SUBJECT_DESCRIPTION);
}

/** The refusal of a token exchange whose `subject_token` names no active user. */
export function inactiveSubjectTokenError(): InvalidRequestError {
  return new InvalidRequestError(INACTIVE_SUBJECT_TOKEN_DESCRIPTION);
}
