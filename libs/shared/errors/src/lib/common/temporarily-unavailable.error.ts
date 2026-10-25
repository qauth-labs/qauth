/**
 * Error thrown when the server refuses a request it is too busy to serve now
 * (RFC 9110 §15.6.4, `503 Service Unavailable`), such as a client-secret check
 * shed because the Argon2 queue is full (#751).
 *
 * The message is the OAuth error code `temporarily_unavailable`, the one OAuth
 * registers for this condition (RFC 6749 §4.1.2.1), so a token, introspection
 * or revocation client reads a code it knows in `error`. RFC 7009 §2.2.1 tells
 * a revocation client to retry a 503 after a delay.
 *
 * {@link retryAfterSeconds} becomes the `Retry-After` header (RFC 9110
 * §10.2.3). {@link details} is for the operator's log line; no response path
 * serializes it.
 */
export class TemporarilyUnavailableError extends Error {
  readonly statusCode = 503;
  readonly code = 'TEMPORARILY_UNAVAILABLE';

  /** Seconds the caller should wait before it tries again. */
  readonly retryAfterSeconds: number;

  /** Operator-facing context, such as why the request was refused. Logged, never sent. */
  readonly details?: Readonly<Record<string, unknown>>;

  /**
   * @param retryAfterSeconds - the `Retry-After` value, a whole number of seconds.
   * @param details - structured context for the operator-facing log.
   */
  constructor(retryAfterSeconds: number, details?: Readonly<Record<string, unknown>>) {
    super('temporarily_unavailable');
    this.name = 'TemporarilyUnavailableError';
    this.retryAfterSeconds = retryAfterSeconds;
    this.details = details;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, TemporarilyUnavailableError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, TemporarilyUnavailableError);
    }
  }
}
