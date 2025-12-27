/**
 * Error thrown when password doesn't meet strength requirements
 */
export class WeakPasswordError extends Error {
  public readonly statusCode = 422;
  public readonly code = 'WEAK_PASSWORD';
  public readonly feedback?: string[];

  constructor(message = 'Password does not meet strength requirements', feedback?: string[]) {
    super(message);
    this.name = 'WeakPasswordError';
    this.feedback = feedback;

    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, WeakPasswordError.prototype);

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, WeakPasswordError);
    }
  }
}
