/**
 * Error thrown when a request's precondition does not hold (RFC 9110 §15.5.13,
 * `412 Precondition Failed`): its `If-Match` names a version of the resource
 * other than the current one, so the change it asks for was made against
 * state that has changed since.
 *
 * The message is fixed and names neither version. The context goes on
 * {@link details}, which the log carries and no response path serializes.
 */
export class PreconditionFailedError extends Error {
  readonly statusCode = 412;
  readonly code = 'PRECONDITION_FAILED';

  /** Operator-facing context, such as the operation. Logged, never sent. */
  readonly details?: Readonly<Record<string, unknown>>;

  /** @param details - structured context for the operator-facing log. */
  constructor(details?: Readonly<Record<string, unknown>>) {
    super('The resource has changed since the version the request names');
    this.name = 'PreconditionFailedError';
    this.details = details;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, PreconditionFailedError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PreconditionFailedError);
    }
  }
}
