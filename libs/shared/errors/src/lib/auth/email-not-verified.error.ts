/**
 * Error thrown when user attempts to login with unverified email
 * Optional check that can be configured per realm
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
