/**
 * Error thrown when a JWT token is invalid (format, signature, etc.)
 */
export class JWTInvalidError extends Error {
  readonly statusCode = 401;
  readonly code = 'JWT_INVALID';

  constructor(message = 'Invalid JWT token') {
    super(message);
    this.name = 'JWTInvalidError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, JWTInvalidError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, JWTInvalidError);
    }
  }
}
