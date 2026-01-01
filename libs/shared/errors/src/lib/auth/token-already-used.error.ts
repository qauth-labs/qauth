/**
 * Error thrown when a token has already been used (CVE-2025-12421 prevention)
 */
export class TokenAlreadyUsedError extends Error {
  readonly statusCode = 409;

  constructor(message = 'Token has already been used') {
    super(message);
    this.name = 'TokenAlreadyUsedError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, TokenAlreadyUsedError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TokenAlreadyUsedError);
    }
  }
}
