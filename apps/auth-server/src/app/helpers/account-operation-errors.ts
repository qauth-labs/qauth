/**
 * The two refusals of the account API's operation guard (#663,
 * `account-operation-guard.ts`), each answered by the error handler as the
 * account contract defines it (`libs/shared/account-contract`, `rules.ts`).
 *
 * Neither document carries prose: no `detail` and no `instance`, as the
 * contract's problem document allows none (`isBareProblem`). The messages are
 * for the log only.
 *
 * Kept free of imports so the registry, and with it the error handler, can
 * load them without loading the guard and its repositories.
 */

/**
 * The step-up challenge of RFC 9470 §3: `401` with the
 * `insufficient_user_authentication` problem document, which carries
 * {@link maxAge} as `max_age`, and the challenge
 * `Bearer error="insufficient_user_authentication", max_age="<maxAge>"` (the
 * `DPoP` scheme for a DPoP-bound token, with its `algs`).
 *
 * `maxAge` is the full window, 300 seconds, when the sign-in behind the token
 * is too old, and `0` when it is recent but lacks the account's strongest
 * bound factor: either way the caller sends the person to the authorization
 * endpoint with that `max_age` and repeats the call with the new token.
 */
export class InsufficientUserAuthenticationError extends Error {
  readonly statusCode = 401;
  readonly code = 'INSUFFICIENT_USER_AUTHENTICATION';
  /** The challenge's `max_age`, in whole seconds. */
  readonly maxAge: number;

  constructor(maxAge = 0) {
    super('The operation needs a fresh sign-in with the account’s strongest bound factor.');
    this.name = 'InsufficientUserAuthenticationError';
    this.maxAge = Number.isSafeInteger(maxAge) && maxAge >= 0 ? maxAge : 0;
  }
}

/**
 * The refusal of an act-chain token (RFC 8693 `act`) on an operation that
 * takes none (ADR-019 Decision 7): `403`, the `delegated_token_refused`
 * problem document. Thrown before any fresh-authentication check, so a
 * delegated caller never gets a challenge it cannot meet.
 */
export class DelegatedTokenRefusedError extends Error {
  readonly statusCode = 403;
  readonly code = 'DELEGATED_TOKEN_REFUSED';

  constructor() {
    super('The operation takes no act-chain token: only the person may do this.');
    this.name = 'DelegatedTokenRefusedError';
  }
}

/**
 * A change the account API refuses because it would leave the account with
 * no way to sign in (#670): `409`, the `last_credential` problem document,
 * such as unlinking the only upstream account of an account that holds no
 * other credential.
 */
export class LastCredentialError extends Error {
  readonly statusCode = 409;
  readonly code = 'LAST_CREDENTIAL';

  constructor() {
    super('The change would leave the account with no way to sign in.');
    this.name = 'LastCredentialError';
  }
}

/**
 * A removal the account API refuses because it would leave the account
 * without the second factor the realm's MFA policy requires of it (#1108):
 * `409`, the `second_factor_required` problem document, such as removing the
 * only passkey of an account that holds no authenticator app while the realm
 * requires a second factor.
 */
export class SecondFactorRequiredError extends Error {
  readonly statusCode = 409;
  readonly code = 'SECOND_FACTOR_REQUIRED';

  constructor() {
    super('The change would remove the last second factor the realm requires of the account.');
    this.name = 'SecondFactorRequiredError';
  }
}

/**
 * A password change whose current password is wrong (#1107): `400`, the
 * `invalid_current_password` problem document. The wrong password counted on
 * the account's failure ladder, as a failed sign-in does. A reset that
 * replaced the password while the change was made is answered the same: the
 * password the caller named is no longer the account's.
 */
export class InvalidCurrentPasswordError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_CURRENT_PASSWORD';

  constructor() {
    super('The current password is not the account’s password.');
    this.name = 'InvalidCurrentPasswordError';
  }
}

/**
 * A one-time code the account API refuses (#1109): `400`, the `invalid_code`
 * problem document, such as a first code that is not the started
 * authenticator-app enrolment's secret's. Nothing was bound, and the
 * enrolment waits for another code.
 */
export class InvalidCodeError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_CODE';

  constructor() {
    super('The code is not valid for this enrolment.');
    this.name = 'InvalidCodeError';
  }
}

/**
 * An account change the account's sign-in methods do not allow as they stand
 * (#1109): `409`, the `conflict` problem document, such as an
 * authenticator-app enrolment for an account that holds one, or a
 * regeneration of recovery codes for an account with no second factor and
 * no passkey. The message names why, for the log only.
 */
export class AccountFactorConflictError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor(reason: string) {
    super(`The account's sign-in methods do not allow the change: ${reason}.`);
    this.name = 'AccountFactorConflictError';
  }
}
