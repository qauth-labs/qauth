import { InvalidCredentialsError } from '@qauth-labs/shared-errors';

import { ISSUER_TRUST_REJECTION_MESSAGE } from '../trust/issuer-trust-rejection';

/**
 * The single, NON-ENUMERATING refusal of the credential-status path (#297).
 *
 * ## Why it reuses the issuer-trust message verbatim
 *
 * `trust/issuer-trust-rejection.ts` establishes the rule for the whole wallet
 * path: every refusal must be the SAME error, because a per-case message is an
 * oracle. Status checking adds a large new family of refusals — the list would
 * not fetch, the token would not verify, the index was past the end, the
 * circuit breaker was open — and if any of them were distinguishable from
 * "issuer not trusted", the guarantee #236 built is gone at the seam this
 * module introduces.
 *
 * So this is not a similar error, it is literally
 * {@link ISSUER_TRUST_REJECTION_MESSAGE} in the same
 * `InvalidCredentialsError` class. A caller — and therefore an attacker —
 * cannot tell a revoked credential from an untrusted issuer from a status
 * endpoint that was down. That is deliberate and must stay true.
 *
 * It matters more here than anywhere else on the path, because the status
 * result is the one piece of information the holder of a credential most wants
 * to probe for: "is my credential revoked yet?" is answerable by anyone who can
 * distinguish a revocation refusal from any other refusal.
 *
 * ## Reasons exist, but only server-side
 *
 * Refusing to say anything on the wire is not refusing to say anything at all.
 * {@link CredentialStatusRejectionReason} is a closed vocabulary carried on the
 * AUDIT event (`credential-status-audit.ts`), so an operator gets a metric per
 * failure mode and an on-call engineer can tell "the status endpoint is down"
 * from "we are rejecting revoked credentials as designed" — a distinction the
 * client is never given.
 */

/**
 * Why the status path refused, for SERVER-SIDE audit and metrics only.
 *
 * Never derive a response, an error message, a status code, or a timing
 * decision from this value. It exists so the operator-facing signal can be
 * precise while the client-facing one stays uniform.
 *
 * - `status-required-but-absent` — the profile mandates a status mechanism
 *   (`VerifierProfile.requireCredentialStatus`) and the credential carried no
 *   `status` claim.
 * - `malformed-status-claim` — a `status` claim was present but is not a
 *   usable `status_list` reference (HAIP §6.1: when `status` is present it MUST
 *   be `status_list`).
 * - `uri-not-permitted` — the status list URI failed the SSRF allowlist.
 * - `endpoint-unavailable` — fetch failed, timed out, returned a non-200, or
 *   served the wrong media type.
 * - `circuit-open` — the breaker for this endpoint is open; no fetch attempted.
 * - `token-unverifiable` — signature, `alg`, `typ`, chain, or expiry check
 *   failed on the Status List Token.
 * - `issuer-untrusted` — the Status List Token's issuer is not trusted by this
 *   realm, or its certificate does not bind to the `iss` it claims.
 * - `list-unreadable` — `status_list` claim malformed, base64url invalid,
 *   decompression failed or exceeded the bomb bound.
 * - `index-out-of-range` — `idx` is past the end of the decoded list.
 * - `revoked` — the bit says `INVALID`.
 * - `suspended` — the bit says `SUSPENDED`.
 * - `status-unknown` — the bit holds a value this verifier has no meaning for.
 */
export type CredentialStatusRejectionReason =
  | 'status-required-but-absent'
  | 'malformed-status-claim'
  | 'uri-not-permitted'
  | 'endpoint-unavailable'
  | 'circuit-open'
  | 'token-unverifiable'
  | 'issuer-untrusted'
  | 'list-unreadable'
  | 'index-out-of-range'
  | 'revoked'
  | 'suspended'
  | 'status-unknown';

/**
 * The message every credential-status refusal carries.
 *
 * Re-exported under its own name so a call site in this module reads honestly,
 * and asserted equal to {@link ISSUER_TRUST_REJECTION_MESSAGE} by test: the
 * two must never be allowed to drift apart, because the moment they differ the
 * status path becomes distinguishable from the trust path.
 */
export const CREDENTIAL_STATUS_REJECTION_MESSAGE = ISSUER_TRUST_REJECTION_MESSAGE;

/**
 * Build the one refusal the credential-status path is allowed to throw (#297).
 *
 * A factory, not a shared instance, for the same reason
 * `issuerTrustRejection()` is: a singleton would carry the stack of whichever
 * request built it first.
 *
 * The `reason` is accepted and DISCARDED on purpose. Taking it here forces
 * every throw site to have named its failure mode — the value that the audit
 * event records — while making it structurally impossible for that name to
 * reach the error, the message, or the wire.
 *
 * @param reason - the server-side failure mode; never attached to the error.
 * @returns an `InvalidCredentialsError` carrying
 * {@link CREDENTIAL_STATUS_REJECTION_MESSAGE}.
 */
export function credentialStatusRejection(
  reason: CredentialStatusRejectionReason
): InvalidCredentialsError {
  // Explicitly discarded rather than named `_reason`: the discard is the
  // POINT of this function, and a leading underscore reads as "left over"
  // instead of "deliberately dropped before it can reach the wire".
  void reason;
  return new InvalidCredentialsError(CREDENTIAL_STATUS_REJECTION_MESSAGE);
}
