/**
 * Error thrown when user credentials are invalid
 * Used for login failures to prevent user enumeration
 */
export class InvalidCredentialsError extends Error {
  readonly statusCode = 401;
  readonly code = 'INVALID_CREDENTIALS';

  constructor(message = 'Invalid email or password') {
    super(message);
    this.name = 'InvalidCredentialsError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, InvalidCredentialsError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidCredentialsError);
    }
  }
}
