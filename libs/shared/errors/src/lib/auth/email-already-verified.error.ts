/**
 * Error thrown when an email is already verified
 */
export class EmailAlreadyVerifiedError extends Error {
  readonly statusCode = 409;
  readonly code = 'EMAIL_ALREADY_VERIFIED';

  constructor(message = 'Email address is already verified') {
    super(message);
    this.name = 'EmailAlreadyVerifiedError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, EmailAlreadyVerifiedError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EmailAlreadyVerifiedError);
    }
  }
}
