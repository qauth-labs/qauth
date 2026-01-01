/**
 * Error thrown when a token is invalid (format, already used, etc.)
 */
export class InvalidTokenError extends Error {
  readonly statusCode = 400;

  constructor(message: string) {
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
