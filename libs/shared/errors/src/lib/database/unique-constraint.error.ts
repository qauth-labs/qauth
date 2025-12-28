/**
 * Error thrown when a unique constraint is violated in the database
 * This is specific to database operations
 */
export class UniqueConstraintError extends Error {
  public readonly statusCode = 409;
  public readonly code = 'UNIQUE_CONSTRAINT_VIOLATION';

  constructor(
    public readonly constraint: string,
    cause?: unknown
  ) {
    super(`Unique constraint violated: ${constraint}`);
    this.name = 'UniqueConstraintError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, UniqueConstraintError.prototype);
    if (cause !== undefined) {
      this.cause = cause;
    }
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UniqueConstraintError);
    }
  }
}
