/**
 * Error thrown when a request is invalid or malformed
 * This is a common error that can occur across different domains
 */
export class BadRequestError extends Error {
  readonly statusCode = 400;

  constructor(message: string) {
    super(message);
    this.name = 'BadRequestError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, BadRequestError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, BadRequestError);
    }
  }
}
