/**
 * Error thrown when password doesn't meet strength requirements
 */
export class WeakPasswordError extends Error {
  public readonly statusCode = 422;
  public readonly code = 'WEAK_PASSWORD';
  public readonly feedback?: string[];
  /**
   * Why the password was refused, as codes a client can branch on (#634,
   * ADR-017 Decision 8): `too_short`, `too_long`, `blocklisted`, `too_weak`.
   * A later release may add codes.
   */
  public readonly reasons?: readonly string[];

  constructor(
    message = 'Password does not meet strength requirements',
    feedback?: string[],
    reasons?: readonly string[]
  ) {
    super(message);
    this.name = 'WeakPasswordError';
    this.feedback = feedback;
    this.reasons = reasons;

    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, WeakPasswordError.prototype);

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, WeakPasswordError);
    }
  }
}
