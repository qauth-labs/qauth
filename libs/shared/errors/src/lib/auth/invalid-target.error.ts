/**
 * Error thrown when an OAuth resource indicator is invalid or unauthorized
 * (RFC 8707 §2.2 `invalid_target`) — the client requested a `resource` that
 * is outside the binding of its grant (authorization code / refresh token /
 * client's configured audience allowlist).
 *
 * Wire format mirrors RFC 6749 §5.2 OAuth error responses: `error`
 * carries the bare `invalid_target` token, with optional
 * `error_description` for human-readable detail.
 */
export class InvalidTargetError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_TARGET';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('invalid_target');
    this.name = 'InvalidTargetError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidTargetError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidTargetError);
    }
  }
}
