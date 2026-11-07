/**
 * Refusal of sender-constrained access tokens.
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
 * Internal: not exported from the package entry points.
 */

import { InvalidTokenError } from './errors.js';

/** The reason given for a token bound to a DPoP key. */
export const DPOP_BOUND_REASON = 'sender-constrained (DPoP-bound) token presented without a proof';

/** The reason given for a token bound by any other confirmation method. */
export const SENDER_CONSTRAINED_REASON = 'sender-constrained token presented without a proof';

/** Whether an introspection `token_type` names DPoP (compared ignoring case, as RFC 6749 §5.1 does). */
function isDpopTokenType(tokenType: unknown): boolean {
  return typeof tokenType === 'string' && tokenType.toLowerCase() === 'dpop';
}

/** Whether a `cnf` value carries the DPoP member `jkt`. */
function hasJwkThumbprint(cnf: unknown): boolean {
  return typeof cnf === 'object' && cnf !== null && 'jkt' in cnf;
}

/**
 * Refuse a sender-constrained token. Call it after the token has been
 * verified, with the verified claims only.
 *
 * @param cnf the token's `cnf` claim (JWT payload) or member (introspection
 *   response). Any value other than `undefined` refuses the token, a malformed
 *   one included, so an unknown confirmation method fails closed.
 * @param tokenType the introspection response's `token_type`, when there is
 *   one. `DPoP` in any case refuses the token even without `cnf`.
 * @throws {InvalidTokenError} when the token is sender-constrained.
 */
export function refuseSenderConstrainedToken(cnf: unknown, tokenType?: unknown): void {
  const dpop = isDpopTokenType(tokenType) || hasJwkThumbprint(cnf);
  if (cnf === undefined && !dpop) {
    return;
  }
  throw new InvalidTokenError(dpop ? DPOP_BOUND_REASON : SENDER_CONSTRAINED_REASON);
}
