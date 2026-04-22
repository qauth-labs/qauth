/**
 * Error thrown when a client is successfully authenticated but is not
 * permitted to use the requested grant type (RFC 6749 Section 5.2
 * `unauthorized_client`).
 *
 * Distinct from `InvalidClientError` (`invalid_client`), which is raised
 * when client authentication itself fails.
 */
export class UnauthorizedClientError extends Error {
  readonly statusCode = 400;
  readonly code = 'UNAUTHORIZED_CLIENT';

  constructor(message = 'unauthorized_client') {
    super(message);
    this.name = 'UnauthorizedClientError';
    Object.setPrototypeOf(this, UnauthorizedClientError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnauthorizedClientError);
    }
  }
}
