/**
 * Error thrown when OAuth client authentication fails (RFC 6749 Section 5.2
 * `invalid_client`) — unknown client, disabled client, missing credentials,
 * or wrong client_secret.
 *
 * Distinct from `InvalidCredentialsError`, which is used for end-user login.
 * Distinct from `UnauthorizedClientError` (`unauthorized_client`), which is
 * raised when the client authenticated successfully but is not allowed the
 * requested grant type.
 */
export class InvalidClientError extends Error {
  readonly statusCode = 401;
  readonly code = 'INVALID_CLIENT';

  constructor(message = 'invalid_client') {
    super(message);
    this.name = 'InvalidClientError';
    Object.setPrototypeOf(this, InvalidClientError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidClientError);
    }
  }
}
