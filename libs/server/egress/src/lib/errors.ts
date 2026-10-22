/**
 * Why an egress call did not complete.
 *
 * - `scheme`: the URL is not an `https` URL (or not a URL at all).
 * - `credentials`: the URL carries a user name or password.
 * - `address`: the host is, or resolves to, an address that is not public.
 * - `redirect`: a redirect past the caller's limit, or one without a usable
 *   `Location`.
 * - `size`: the request body or the response body is above its cap.
 * - `timeout`: the connect time or the total time ran out.
 * - `network`: the name did not resolve, or the connection, the TLS handshake
 *   or the HTTP exchange failed.
 *
 * A redirect target is checked by the same rules as the first URL, so a
 * redirect to `http` is refused with `scheme` and one to a private address with
 * `address`.
 */
export type EgressErrorReason =
  'scheme' | 'credentials' | 'address' | 'redirect' | 'size' | 'timeout' | 'network';

/**
 * `blocked`: a check refused the call, and nothing more was sent to the
 * destination it refused. `failed`: the destination was contacted, or tried,
 * and the call did not complete.
 */
export type EgressOutcome = 'blocked' | 'failed';

/**
 * A refusal or failure inside the client, before it knows the caller's
 * purpose. {@link EgressError} is what leaves the client.
 *
 * @internal
 */
export class EgressFailure extends Error {
  constructor(
    readonly reason: EgressErrorReason,
    readonly outcome: EgressOutcome,
    message: string
  ) {
    super(message);
    this.name = 'EgressFailure';
    Object.setPrototypeOf(this, EgressFailure.prototype);
  }
}

/**
 * The one error an egress call rejects with. Its message names the host, never
 * the path, the query string or a header, so a caller may log it as it is.
 */
export class EgressError extends Error {
  /** Why the call did not complete. */
  readonly reason: EgressErrorReason;
  /** Whether a check refused the call or the call failed. */
  readonly outcome: EgressOutcome;
  /** The caller's purpose label. */
  readonly purpose: string;
  /** The host name of the destination that was refused or failed, if any. */
  readonly host: string | undefined;

  constructor(options: {
    reason: EgressErrorReason;
    outcome: EgressOutcome;
    purpose: string;
    host: string | undefined;
    message: string;
  }) {
    super(options.message);
    this.name = 'EgressError';
    this.reason = options.reason;
    this.outcome = options.outcome;
    this.purpose = options.purpose;
    this.host = options.host;
    Object.setPrototypeOf(this, EgressError.prototype);
  }
}

/** True when `error` is an {@link EgressError}. */
export function isEgressError(error: unknown): error is EgressError {
  return error instanceof EgressError;
}
