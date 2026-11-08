/**
 * The refusal of an operator's verification of an account (ADR-015
 * Decision 8, amended 2026-11-08; issue #1052), answered as a problem
 * document (`api-conventions/error-classes.ts`).
 *
 * Kept free of imports so the error registry, and with it the error handler,
 * can load it without loading a route.
 */

/** Why an account cannot be verified by an operator now. */
export type AccountVerificationRefusal = 'disabled' | 'already_verified';

const MESSAGES: Readonly<Record<AccountVerificationRefusal, string>> = Object.freeze({
  disabled: 'The account is disabled: an operator verifies only an enabled account.',
  already_verified: 'An operator has already verified the account.',
});

/**
 * An account an operator cannot verify as it stands: `409`, the `conflict`
 * problem document. A disabled account is refused, and so is one an operator
 * already verified, whose first verification is kept.
 */
export class AccountVerificationConflictError extends Error {
  readonly statusCode = 409;
  readonly code = 'CONFLICT';

  constructor(readonly refusal: AccountVerificationRefusal) {
    super(MESSAGES[refusal]);
    this.name = 'AccountVerificationConflictError';
  }
}
