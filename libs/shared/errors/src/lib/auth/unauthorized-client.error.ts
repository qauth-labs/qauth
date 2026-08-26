/**
 * Error thrown when a client is successfully authenticated but is not
 * permitted to use the requested grant type (RFC 6749 Section 5.2
 * `unauthorized_client`).
 *
 * Distinct from `InvalidClientError` (`invalid_client`), which is raised
 * when client authentication itself fails.
 *
 * The constructor argument is the §5.2 `error_description`, not the message —
 * see {@link import('./invalid-client.error').InvalidClientError} for why the
 * message is always the registered code.
 */
export class UnauthorizedClientError extends Error {
  readonly statusCode = 400;
  readonly code = 'UNAUTHORIZED_CLIENT';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('unauthorized_client');
    this.name = 'UnauthorizedClientError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, UnauthorizedClientError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnauthorizedClientError);
    }
  }
}
