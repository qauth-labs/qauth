/**
 * Error thrown when an OAuth scope request is rejected (RFC 6749 Section 5.2
 * `invalid_scope`) — a scope is not in the client's allowlist, or a required
 * scope is missing.
 *
 * The human-readable detail lives in `errorDescription` so the wire response
 * can carry `error: "invalid_scope"` (unchanged token) and a separate
 * `error_description` field.
 */
export class InvalidScopeError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_SCOPE';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('invalid_scope');
    this.name = 'InvalidScopeError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidScopeError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidScopeError);
    }
  }
}
