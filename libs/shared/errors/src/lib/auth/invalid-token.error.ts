/**
 * Error thrown when an email verification token is not valid: unknown,
 * malformed, already spent or expired (`/auth/verify` answers all of them
 * alike). Its code is `INVALID_VERIFICATION_TOKEN`: it is a one-time token,
 * never an access token, which `JWTInvalidError` covers.
 */
export class InvalidTokenError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_VERIFICATION_TOKEN';

  constructor(message = 'Invalid or expired verification token') {
    super(message);
    this.name = 'InvalidTokenError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, InvalidTokenError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidTokenError);
    }
  }
}
