/**
 * Error thrown when a DPoP proof is refused (RFC 9449 §4.3): the
 * `invalid_dpop_proof` error code of RFC 9449 §12.2.
 *
 * Where it is answered decides its status:
 *
 * - at the token endpoint, 400 with the RFC 6749 §5.2 error body (RFC 9449
 *   §5), for a missing or invalid proof, or one under another key than the
 *   code or refresh token is bound to;
 * - at a protected resource, 401 with a `WWW-Authenticate: DPoP` challenge
 *   whose `error` is `invalid_dpop_proof` (RFC 9449 §7.1), when the request
 *   used the DPoP scheme and its proof failed a check.
 *
 * `error` carries the bare code. Which check failed is never on the wire: a
 * response that named it would help an attacker tune a forged proof. The
 * server logs it and records it in the event.
 */
export class InvalidDpopProofError extends Error {
  readonly statusCode: 400 | 401;
  readonly code = 'INVALID_DPOP_PROOF';
  readonly errorDescription?: string;

  constructor(errorDescription?: string, options: { atResource?: boolean } = {}) {
    super('invalid_dpop_proof');
    this.name = 'InvalidDpopProofError';
    this.statusCode = options.atResource ? 401 : 400;
    this.errorDescription = errorDescription;
    Object.setPrototypeOf(this, InvalidDpopProofError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, InvalidDpopProofError);
    }
  }
}
