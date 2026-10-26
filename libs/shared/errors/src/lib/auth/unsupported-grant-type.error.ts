/**
 * Error thrown when the token endpoint does not support the `grant_type` a
 * request names (RFC 6749 §5.2 `unsupported_grant_type`): an unknown value, or
 * a grant this deployment has switched off.
 *
 * Wire format mirrors RFC 6749 §5.2 OAuth error responses: `error`
 * carries the bare `unsupported_grant_type` token, with optional
 * `error_description` for human-readable detail.
 */
export class UnsupportedGrantTypeError extends Error {
  readonly statusCode = 400;
  readonly code = 'UNSUPPORTED_GRANT_TYPE';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('unsupported_grant_type');
    this.name = 'UnsupportedGrantTypeError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, UnsupportedGrantTypeError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, UnsupportedGrantTypeError);
    }
  }
}
