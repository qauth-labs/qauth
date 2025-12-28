/**
 * Error thrown when an entity is not found in the database
 * This is a common error that can occur across different domains
 */
export class NotFoundError extends Error {
  readonly statusCode = 404;

  constructor(entity: string, id: string) {
    super(`${entity} with id ${id} not found`);
    this.name = 'NotFoundError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, NotFoundError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NotFoundError);
    }
  }
}
