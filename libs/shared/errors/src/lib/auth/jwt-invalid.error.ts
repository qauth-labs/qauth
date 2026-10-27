/**
 * Error thrown when an access token that was presented is not valid (format,
 * signature, audience, subject, etc.). A request that presented none gets a
 * `MissingAccessTokenError`.
 */
export class JWTInvalidError extends Error {
  readonly statusCode = 401;
  readonly code = 'INVALID_ACCESS_TOKEN';

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
