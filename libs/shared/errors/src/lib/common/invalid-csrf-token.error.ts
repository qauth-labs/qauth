/**
 * Error thrown when a cookie-authenticated request that changes state carries
 * no CSRF token, or one that does not match the browser session's.
 */
export class InvalidCsrfTokenError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_CSRF_TOKEN';

  constructor(message = 'The CSRF token is missing or does not match the session') {
    super(message);
    this.name = 'InvalidCsrfTokenError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, InvalidCsrfTokenError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidCsrfTokenError);
    }
  }
}
