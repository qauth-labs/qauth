import { InvalidCredentialsError } from '@qauth-labs/shared-errors';

import { ISSUER_TRUST_REJECTION_MESSAGE } from '../trust/issuer-trust-rejection';

/**
 * The single, NON-ENUMERATING refusal of the key-storage-assurance path (#308).
 *
 * ## Distinct outcomes, one wire shape — the pattern this path inherits
 *
 * #308 asks for *"distinct, non-enumerating domain errors"* for six different
 * failures. Those two words pull in opposite directions only if "distinct" is
 * read as "distinct on the wire", and `trust/issuer-trust-rejection.ts` already
 * settled that for the whole wallet path: a per-case message is an oracle, so
 * every refusal renders the SAME error. `status/credential-status-rejection.ts`
 * (#297) made the same split first, and this module is deliberately its twin.
 *
 * So {@link KeyStorageAssuranceRejectionReason} is a closed, precise vocabulary
 * for the SERVER — logs, metrics, an operator debugging a wallet ecosystem's
 * attestation format — and it never reaches a client.
 *
 * It matters acutely here. The failures this path can report are, between them,
 * a description of the holder's device: whether their key lives in certified
 * hardware, at what level it is certified, and whether their wallet vendor's
 * attestation chain is one this deployment anchors. A client able to tell
 * `attack-potential-below-minimum` from `assurance-required-but-absent` learns
 * facts about a stranger's hardware from a login attempt, and an attacker
 * learns exactly which lie to tell next.
 *
 * ## Why not `PresentationValidationRejection`
 *
 * This gate is reachable from two places: inside SD-JWT VC validation, and — as
 * #237 will use it — on its own, over a credential that some other adapter
 * validated. A rejection type owned by one format's validator would force the
 * second caller to import that validator to read an error. The presentation
 * seam adapts this into its own vocabulary at the boundary (see
 * `oid4vp/sd-jwt-vc.ts`), so a caller of `validateSdJwtVcPresentation` still
 * sees exactly one error contract.
 */

/**
 * Why key-storage assurance was refused, for SERVER-SIDE audit and metrics only.
 *
 * Never derive a response, an error message, a status code, or a timing
 * decision from this value.
 *
 * - `assurance-required-but-absent` — the active profile requires key-storage
 *   assurance and neither a conveyed attestation nor the transitive
 *   trusted-issuer path established any. The default refusal, and the one that
 *   makes "fail-closed" true rather than aspirational.
 * - `issuer-does-not-attest-key-storage` — the credential's validated issuer is
 *   not one the operator recorded as a HAIP issuance chain that validates key
 *   attestations at issuance (HAIP §4.5.1), so the transitive path establishes
 *   nothing about it. An INTERMEDIATE finding rather than a verdict: a
 *   `required` posture narrows it to `assurance-required-but-absent` (the
 *   profile's requirement is what was not met), and a `permitted` posture is not
 *   refused by it at all. Kept distinct because it is the one failure an
 *   operator can act on — it names a missing registry entry, not a bad
 *   credential.
 * - `attestation-malformed` — a key attestation WAS conveyed but is not a usable
 *   Appendix D attestation: not a compact JWS, wrong `typ`, no `attested_keys`,
 *   no `iat`, or a claim of the wrong JSON shape.
 * - `attestation-certificate-self-signed` — the certificate signing the
 *   attestation is self-signed. HAIP §4.5.1: *"The X.509 certificate signing the
 *   key attestation MUST NOT be self-signed."*
 * - `attestation-anchor-in-chain` — the `x5c` header carries the trust anchor.
 *   HAIP §4.5.1: *"The X.509 certificate of the trust anchor MUST NOT be
 *   included in the `x5c` JOSE header."*
 * - `attestation-chain-unanchored` — the `x5c` chain does not reach an anchor
 *   this deployment configured, a link in it does not verify, or a certificate
 *   in it is outside its validity window. An unanchored attestation is a
 *   self-assertion: anyone can mint a CA and attest their own software key.
 * - `attestation-signature-invalid` — a key WAS resolved from the chain and the
 *   attestation JWS did not verify under it (or the attestation has expired).
 * - `attested-key-mismatch` — the attestation is sound but attests a key that is
 *   not the credential's holder-binding (`cnf`) key. Without this check an
 *   attacker replays ANY genuine attestation — one for a real hardware key,
 *   published or captured — alongside a credential bound to a software key they
 *   control, and buys hardware assurance for a key that never had it.
 * - `attack-potential-below-minimum` — assurance was established, and it is
 *   weaker than the floor the active profile declares.
 */
export type KeyStorageAssuranceRejectionReason =
  | 'assurance-required-but-absent'
  | 'issuer-does-not-attest-key-storage'
  | 'attestation-malformed'
  | 'attestation-certificate-self-signed'
  | 'attestation-anchor-in-chain'
  | 'attestation-chain-unanchored'
  | 'attestation-signature-invalid'
  | 'attested-key-mismatch'
  | 'attack-potential-below-minimum';

/**
 * The message every key-storage-assurance refusal carries.
 *
 * Re-exported under its own name so a call site in this module reads honestly,
 * and asserted equal to {@link ISSUER_TRUST_REJECTION_MESSAGE} by test: the two
 * must never drift apart, because the moment they differ this path becomes
 * distinguishable from the trust path and from the status path.
 */
export const KEY_STORAGE_ASSURANCE_REJECTION_MESSAGE = ISSUER_TRUST_REJECTION_MESSAGE;

/**
 * Build the one refusal the key-storage-assurance path is allowed to throw.
 *
 * A factory, not a shared instance, for the same reason `issuerTrustRejection()`
 * is: a singleton would carry the stack of whichever request built it first.
 *
 * The `reason` is accepted and DISCARDED on purpose. Taking it here forces every
 * throw site to have named its failure mode — the value an audit record keeps —
 * while making it structurally impossible for that name to reach the error, the
 * message, or the wire.
 *
 * @param reason - the server-side failure mode; never attached to the error.
 * @returns an `InvalidCredentialsError` carrying
 * {@link KEY_STORAGE_ASSURANCE_REJECTION_MESSAGE}.
 */
export function keyStorageAssuranceRejection(
  reason: KeyStorageAssuranceRejectionReason
): InvalidCredentialsError {
  // Explicitly discarded rather than named `_reason`: the discard is the POINT
  // of this function, and a leading underscore reads as "left over" instead of
  // "deliberately dropped before it can reach the wire".
  void reason;
  return new InvalidCredentialsError(KEY_STORAGE_ASSURANCE_REJECTION_MESSAGE);
}
