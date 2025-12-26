/**
 * Error thrown when a unique constraint is violated in the database
 * This is specific to database operations
 */
export class UniqueConstraintError extends Error {
  readonly statusCode = 409;

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
  }
}
