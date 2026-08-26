/**
 * Error thrown when OAuth client authentication fails (RFC 6749 Section 5.2
 * `invalid_client`) — unknown client, disabled client, missing credentials,
 * or wrong client_secret.
 *
 * Distinct from `InvalidCredentialsError`, which is used for end-user login.
 * Distinct from `UnauthorizedClientError` (`unauthorized_client`), which is
 * raised when the client authenticated successfully but is not allowed the
 * requested grant type.
 *
 * ## The message is the RFC CODE, never prose (#365)
 *
 * `error` on the wire is a registered §5.2 token and an OAuth client library
 * branches on it, so the constructor argument is an `errorDescription` — the
 * separate, free-text §5.2 field — exactly as `InvalidGrantError` and
 * `InvalidScopeError` already treat theirs. It used to be the MESSAGE, so a
 * call site passing detail replaced `invalid_client` on the wire with a
 * sentence: `{"error": "CIMD document is not valid JSON"}` where the
 * specification requires `{"error": "invalid_client", "error_description":
 * "CIMD document is not valid JSON"}`. Nothing keying off the code could read
 * it, and the two forms differed depending on which call site threw.
 *
 * Passing no description keeps the response to the bare code, which is what
 * `helpers/client-auth.ts` does deliberately: an authentication failure must
 * not describe itself, or the response becomes a client-enumeration oracle.
 */
export class InvalidClientError extends Error {
  readonly statusCode = 401;
  readonly code = 'INVALID_CLIENT';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('invalid_client');
    this.name = 'InvalidClientError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidClientError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidClientError);
    }
  }
}
