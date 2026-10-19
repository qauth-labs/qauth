/**
 * Error thrown when user attempts to login with unverified email
 * Optional check that can be configured per realm
 *
 * The auth-server's password login routes do NOT throw it: they refuse an
 * unverified account with the same `InvalidCredentialsError` as a wrong
 * password. A distinct answer lets anyone who registered an address with a
 * password of their choice learn, at login, whether the address was free.
 */
export class EmailNotVerifiedError extends Error {
  readonly statusCode = 403;
  readonly code = 'EMAIL_NOT_VERIFIED';

  constructor(message = 'Email address not verified') {
    super(message);
    this.name = 'EmailNotVerifiedError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, EmailNotVerifiedError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EmailNotVerifiedError);
    }
  }
}
