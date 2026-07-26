import { InvalidCredentialsError } from '@qauth-labs/shared-errors';

/**
 * The single, NON-ENUMERATING refusal of the wallet trust path (issue #236).
 *
 * ## Why one error, and only one
 *
 * #236 requires that a presentation from an untrusted issuer is rejected
 * *"with a clear, non-enumerating domain error (no leakage of which issuers are
 * or are not configured)"*. That property is not achieved by wording a message
 * carefully — it is achieved by making every failure on this path produce the
 * SAME error, so an attacker probing with credentials from different issuers
 * learns nothing from the difference between responses. Concretely, all of the
 * following are indistinguishable:
 *
 *   - the realm has no allowlist configured at all;
 *   - the realm has an allowlist and this issuer is not on it;
 *   - the issuer identity was never validated (a forged or raw `iss`);
 *   - the issuer identifier is malformed and cannot be canonicalized.
 *
 * A per-case message ("issuer not in allowlist" vs "no issuers configured")
 * would be a membership oracle: it tells the caller whether the realm has a
 * list, and — probed issuer by issuer — what is on it.
 *
 * **#234 must reuse this for MALFORMED presentations too.** The lane rule is
 * that an untrusted issuer must not be distinguishable from a malformed one;
 * if presentation validation rejects a bad signature with its own distinct
 * error, the difference between "bad credential" and "good credential, wrong
 * issuer" becomes observable again and the guarantee is lost at the seam.
 *
 * ## Why `InvalidCredentialsError`
 *
 * A domain error from `@qauth-labs/shared-errors` rather than a plain `Error`
 * — unlike `profiles/verifier-identity.ts`, which throws plain errors because
 * reaching one means the DEPLOYMENT is mis-provisioned. This path is different:
 * the input is attacker-controlled, so a 500 with a stack trace would be wrong
 * on both counts. `InvalidCredentialsError` (401, `INVALID_CREDENTIALS`) is the
 * class this codebase already uses precisely to keep authentication failures
 * indistinguishable from one another.
 *
 * Never attach the issuer identifier, the realm, or the allowlist to the thrown
 * error. Log those server-side at the call site if they are needed.
 */

/**
 * The message every trust-path refusal carries.
 *
 * Deliberately says nothing about issuers, allowlists or realms. It names the
 * artefact that was rejected and stops there.
 */
export const ISSUER_TRUST_REJECTION_MESSAGE = 'Verifiable Presentation rejected';

/**
 * Build the one refusal the wallet trust path is allowed to throw (#236).
 *
 * A factory rather than a shared singleton instance: a single frozen error
 * would carry the stack trace of whichever request happened to construct it
 * first, which makes server-side debugging actively misleading. Every throw
 * gets its own stack; the client-visible shape is identical either way.
 *
 * @returns an `InvalidCredentialsError` carrying
 * {@link ISSUER_TRUST_REJECTION_MESSAGE}.
 */
export function issuerTrustRejection(): InvalidCredentialsError {
  return new InvalidCredentialsError(ISSUER_TRUST_REJECTION_MESSAGE);
}
