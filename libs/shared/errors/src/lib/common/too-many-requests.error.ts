/**
 * Error thrown when rate limit is exceeded
 * This is a common error that can occur across different domains
 */
export class TooManyRequestsError extends Error {
  readonly statusCode = 429;

  constructor(message = 'Too many requests') {
    super(message);
    this.name = 'TooManyRequestsError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, TooManyRequestsError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TooManyRequestsError);
    }
  }
}
