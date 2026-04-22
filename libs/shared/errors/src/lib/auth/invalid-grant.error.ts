/**
 * Error thrown when an OAuth grant fails validation (RFC 6749 Section 5.2
 * `invalid_grant`) — authorization code unknown, expired, already used,
 * client-mismatched, redirect_uri mismatch, or PKCE verification failure;
 * also refresh-token rotation failures in the OAuth-spec surface.
 *
 * Human-readable detail lives in `errorDescription` so the wire response
 * carries the bare `error: "invalid_grant"` token plus a separate
 * `error_description` field. Standard OAuth client libraries key off this
 * exact error code for code-replay detection and retry behaviour.
 */
export class InvalidGrantError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_GRANT';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('invalid_grant');
    this.name = 'InvalidGrantError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidGrantError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidGrantError);
    }
  }
}
