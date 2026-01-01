/**
 * Error thrown when a token has expired
 */
export class TokenExpiredError extends Error {
  readonly statusCode = 410;

  constructor(message = 'Token has expired') {
    super(message);
    this.name = 'TokenExpiredError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, TokenExpiredError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenExpiredError);
    }
  }
}
