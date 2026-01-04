/**
 * Error thrown when a JWT token has expired
 */
export class JWTExpiredError extends Error {
  readonly statusCode = 401;
  readonly code = 'JWT_EXPIRED';

  constructor(message = 'JWT token has expired') {
    super(message);
    this.name = 'JWTExpiredError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, JWTExpiredError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, JWTExpiredError);
    }
  }
}
