/**
 * Error thrown when a route that takes an access token gets a request that
 * presents none: no `Authorization` header, an empty token, or a scheme the
 * route does not accept (HTTP 401).
 *
 * RFC 6750 §3.1 tells it apart from a token that was presented and refused
 * (`JWTInvalidError`): the request "lacks any authentication information", so
 * the challenge carries no error code. Its code is `UNAUTHORIZED`, the code
 * every route answers a request without credentials with; the auth server
 * still answers `error: "invalid_token"` in the body of an OAuth protected
 * resource such as userinfo, where the body needs an `error`.
 */
export class MissingAccessTokenError extends Error {
  readonly statusCode = 401;
  readonly code = 'UNAUTHORIZED';

  constructor(message = 'The request carries no access token') {
    super(message);
    this.name = 'MissingAccessTokenError';
    // Ensure proper prototype chain for instanceof checks
    Object.setPrototypeOf(this, MissingAccessTokenError.prototype);
    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, MissingAccessTokenError);
    }
  }
}
