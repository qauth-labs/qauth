/**
 * Refusal of every access token that is not a plain bearer token.
 *
 * A token that carries a `cnf` (confirmation) claim (RFC 7800 §3) is bound to
 * a key. A DPoP-bound token names that key's thumbprint in `cnf.jkt` (RFC 9449
 * §6) and is reported by introspection with `token_type: DPoP` (RFC 9449
 * §6.2). A certificate-bound token names a certificate in `cnf["x5t#S256"]`
 * (RFC 8705 §3.1). Other confirmation methods exist. Whatever the method, the
 * holder must prove possession of the key on every request, and the resource
 * server must check that proof before it grants access (RFC 9449 §7.1, RFC
 * 8705 §3). Accepting such a token as a plain bearer would let anyone who
 * copied it use it, which is exactly the theft binding exists to stop
 * (RFC 9449 §7.2).
 *
 * This version of the SDK verifies no proof of possession of any kind, so it
 * refuses every sender-constrained token outright. QAuth's own protected
 * routes refuse a bound token presented as a Bearer token in the same way.
 *
 * An introspection `token_type` is read as an allow-list, not a deny-list:
 * only an absent one or `Bearer` is a token this SDK can accept. Another
 * authorization server may name a bound token type this SDK has never heard
 * of (`PoP`, a misspelt `DPoP`, a non-string value), and a deny-list would let
 * it through as a bearer token.
 *
 * Internal: not exported from the package entry points.
 */

import { InvalidTokenError } from './errors.js';

/** The reason given for a token bound to a DPoP key. */
export const DPOP_BOUND_REASON = 'sender-constrained (DPoP-bound) token presented without a proof';

/** The reason given for a token bound by any other confirmation method. */
export const SENDER_CONSTRAINED_REASON = 'sender-constrained token presented without a proof';

/** The reason given for an introspected `token_type` that is neither absent nor `Bearer`. */
export const NOT_BEARER_REASON = 'token type is not Bearer';

/**
 * Whether an introspection `token_type` is `want`, compared ignoring case as
 * RFC 6749 §5.1 says, but otherwise exactly: no trimming, strings only.
 */
function isTokenType(tokenType: unknown, want: string): boolean {
  return typeof tokenType === 'string' && tokenType.toLowerCase() === want;
}

/** Whether a `cnf` value carries the DPoP member `jkt`. */
function hasJwkThumbprint(cnf: unknown): boolean {
  return typeof cnf === 'object' && cnf !== null && 'jkt' in cnf;
}

/**
 * Refuse a token that is not a plain bearer token. Call it after the token
 * has been verified, with the verified claims only.
 *
 * @param cnf the token's `cnf` claim (JWT payload) or member (introspection
 *   response). Any value other than `undefined` refuses the token, a malformed
 *   one included, so an unknown confirmation method fails closed.
 * @param tokenType the introspection response's `token_type`, when there is
 *   one. Only `undefined` (absent) or `Bearer` in any case is accepted; `DPoP`
 *   is refused as DPoP-bound, and any other value as not Bearer. The JWT
 *   validator passes nothing, since a JWT carries no `token_type`.
 * @throws {InvalidTokenError} when the token is sender-constrained or its type
 *   is not Bearer.
 */
export function refuseNonBearerToken(cnf: unknown, tokenType?: unknown): void {
  if (isTokenType(tokenType, 'dpop') || hasJwkThumbprint(cnf)) {
    throw new InvalidTokenError(DPOP_BOUND_REASON);
  }
  if (cnf !== undefined) {
    throw new InvalidTokenError(SENDER_CONSTRAINED_REASON);
  }
  if (tokenType !== undefined && !isTokenType(tokenType, 'bearer')) {
    throw new InvalidTokenError(NOT_BEARER_REASON);
  }
}
