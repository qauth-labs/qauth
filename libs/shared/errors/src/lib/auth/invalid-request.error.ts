/**
 * Error thrown when an OAuth request is malformed or otherwise unacceptable
 * (RFC 6749 §5.2 `invalid_request`, RFC 8693 §2.2.2) — e.g. an unsupported
 * token type, an unverifiable / non-conformant `subject_token`, or a
 * delegation chain that exceeds policy limits at the token endpoint.
 *
 * Human-readable detail lives in `errorDescription` so the wire response
 * carries the bare `error: "invalid_request"` token plus a separate
 * `error_description` field. OAuth client libraries key off the exact bare
 * code (RFC 6749 §5.2), so the sentence MUST NOT be folded into `error`.
 */
export class InvalidRequestError extends Error {
  readonly statusCode = 400;
  readonly code = 'INVALID_REQUEST';
  readonly errorDescription?: string;

  constructor(errorDescription?: string) {
    super('invalid_request');
    this.name = 'InvalidRequestError';
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidRequestError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidRequestError);
    }
  }
}
