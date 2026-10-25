/**
 * Error thrown when a valid access token lacks a scope the protected resource
 * requires (RFC 6750 §3.1 `insufficient_scope`, HTTP 403).
 *
 * The resource answers with a `WWW-Authenticate: Bearer` challenge whose
 * `error` is `insufficient_scope` and whose `scope` names the scopes the
 * request needs, {@link requiredScopes}, so the client can ask for a token
 * that carries them. Distinct from `ForbiddenError`: the caller could
 * succeed with another token, not only with other rights.
 *
 * Wire format mirrors the other OAuth errors: `error` carries the bare
 * `insufficient_scope` token, with optional `error_description`.
 */
export class InsufficientScopeError extends Error {
  readonly statusCode = 403;
  readonly code = 'INSUFFICIENT_SCOPE';
  readonly errorDescription?: string;
  /** The scopes the request needs, in the order the resource lists them. */
  readonly requiredScopes: readonly string[];

  constructor(requiredScopes: readonly string[], errorDescription?: string) {
    super('insufficient_scope');
    this.name = 'InsufficientScopeError';
    this.requiredScopes = [...requiredScopes];
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InsufficientScopeError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InsufficientScopeError);
    }
  }
}
