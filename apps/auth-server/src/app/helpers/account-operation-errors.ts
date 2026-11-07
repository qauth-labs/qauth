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
