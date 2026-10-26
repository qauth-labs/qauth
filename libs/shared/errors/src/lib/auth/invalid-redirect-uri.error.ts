/**
 * Error thrown when a client registration names a redirect URI the server
 * refuses (RFC 7591 §3.2.2 `invalid_redirect_uri`): one that does not parse,
 * carries a fragment, or uses a scheme the deployment does not allow.
 *
 * Wire format mirrors RFC 7591 §3.2.2: `error` carries the bare
 * `invalid_redirect_uri` token, with optional `error_description` for
 * human-readable detail.
 */
export class InvalidRedirectUriError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_REDIRECT_URI';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('invalid_redirect_uri');
    this.name = 'InvalidRedirectUriError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidRedirectUriError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidRedirectUriError);
    }
  }
}
