/**
 * Error thrown when an email is already verified
 */
export class EmailAlreadyVerifiedError extends Error {
  readonly statusCode = 409;

  constructor(message = 'Email is already verified') {
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
