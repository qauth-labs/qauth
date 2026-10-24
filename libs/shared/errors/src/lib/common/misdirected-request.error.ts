/**
 * Error thrown when a request names a host this server does not answer for
 * (RFC 9110 §15.5.20, `421 Misdirected Request`).
 *
 * The auth server answers it when no enabled realm with an issuer owns the
 * request's host, and when a browser-session endpoint is asked for on a realm's
 * endpoint host (ADR-019 Decision 1).
 *
 * The message is fixed: it never names the host, the realm or the reason, so
 * the answer is the same for an unknown host, a disabled realm and a realm with
 * no issuer. The reason and the host go on {@link details}, which the log
 * carries and no response path serializes.
 */
export class MisdirectedRequestError extends Error {
  readonly statusCode = 421;
  readonly code = 'MISDIRECTED_REQUEST';

  /** Operator-facing context, such as why the host was refused. Logged, never sent. */
  readonly details?: Readonly<Record<string, unknown>>;

  /** @param details - structured context for the operator-facing log. */
  constructor(details?: Readonly<Record<string, unknown>>) {
    super('This server does not answer for the requested host');
    this.name = 'MisdirectedRequestError';
    this.details = details;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, MisdirectedRequestError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, MisdirectedRequestError);
    }
  }
}
