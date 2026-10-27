/**
 * Error thrown when a request is authenticated but not permitted to perform the
 * requested action (HTTP 403). Distinct from a 401 (missing/invalid auth) and a
 * 404 (resource hidden for object-level authorization): use this when the
 * action itself is refused by policy.
 *
 * In QAuth this carries the ADR-008 environment gate: attempting to mint a
 * static developer API key for a `production` (or unset-environment) client is
 * refused with this error and a message pointing the developer at OAuth
 * `client_credentials`.
 *
 * `requiredScope` is set only when a token with that scope would be let
 * through: the auth server's challenge then says `insufficient_scope` (RFC
 * 6750 §3.1). A refusal no scope can lift, such as the gate above, leaves it
 * unset. It is the challenge's `scope` attribute: one scope, or several
 * separated by a space (RFC 6750 §3), as a route that needs several passes
 * them as a list (#509). An empty list sets nothing.
 */
export class ForbiddenError extends Error {
  readonly statusCode = 403;
  readonly code = 'FORBIDDEN';
  readonly requiredScope?: string;

  constructor(message = 'Forbidden', options: { requiredScope?: string | readonly string[] } = {}) {
    super(message);
    this.name = 'ForbiddenError';
    const { requiredScope } = options;
    const scope = typeof requiredScope === 'string' ? requiredScope : requiredScope?.join(' ');
    this.requiredScope = scope === undefined || scope.length === 0 ? undefined : scope;
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, ForbiddenError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, ForbiddenError);
    }
  }
}
