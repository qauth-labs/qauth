/**
 * Error thrown when a request must be conditional and is not (RFC 6585 §3,
 * `428 Precondition Required`): it changes a resource whose current state
 * decides what the change needs, and names no version of it in `If-Match`.
 *
 * The message is fixed. The context goes on {@link details}, which the log
 * carries and no response path serializes.
 */
export class PreconditionRequiredError extends Error {
  readonly statusCode = 428;
  readonly code = 'PRECONDITION_REQUIRED';

  /** Operator-facing context, such as the operation. Logged, never sent. */
  readonly details?: Readonly<Record<string, unknown>>;

  /** @param details - structured context for the operator-facing log. */
  constructor(details?: Readonly<Record<string, unknown>>) {
    super('The request must name the version of the resource it changes, in If-Match');
    this.name = 'PreconditionRequiredError';
    this.details = details;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, PreconditionRequiredError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PreconditionRequiredError);
    }
  }
}
