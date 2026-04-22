/**
 * Error thrown when a client is successfully authenticated but is not
 * permitted to use the requested grant type (RFC 6749 Section 5.2
 * `unauthorized_client`).
 *
 * Distinct from `InvalidCredentialsError` (which maps to `invalid_client`
 * — client auth itself failed).
 */
export class UnauthorizedClientError extends Error {
  readonly statusCode = 401;
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
