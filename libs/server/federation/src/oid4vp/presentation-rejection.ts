/**
 * Presentation-validation refusals (issue #234).
 *
 * ## Two audiences, one wire shape
 *
 * #234 asks for "distinct outcomes" for an invalid issuer signature, an expired
 * credential, a disclosure-digest mismatch, a holder-binding failure and an
 * unsupported Credential Format. #236's `issuer-trust-rejection.ts` asks for the
 * exact opposite on the wire:
 *
 * > **#234 must reuse this for MALFORMED presentations too.** [...] if
 * > presentation validation rejects a bad signature with its own distinct error,
 * > the difference between "bad credential" and "good credential, wrong issuer"
 * > becomes observable again and the guarantee is lost at the seam.
 *
 * Both are satisfiable at once, and only by splitting the audiences — the same
 * split `direct-post.ts` already makes for the transport layer. The
 * {@link PresentationRejectionReason} is a precise, machine-readable outcome for
 * the SERVER (logs, metrics, a wallet-integration bug report); every one of them
 * renders to the byte-identical {@link import('../trust/issuer-trust-rejection')}
 * refusal on the wire.
 *
 * So: a caller may branch on `reason` for logging. A caller may NOT put `reason`,
 * `detail`, or this error's `message` on a response. Use
 * {@link PresentationValidationRejection.toClientError}.
 *
 * ## Why the reasons are enumerated at all
 *
 * A single opaque failure would make this layer undebuggable: an operator
 * integrating a wallet needs to know whether the credential was expired or the
 * `sd_hash` did not match, and "Verifiable Presentation rejected" tells them
 * nothing. The enumeration is also what makes the rejection paths TESTABLE — a
 * test asserting "it threw" cannot tell a digest check that fired for the right
 * reason from one that fired because the signature check was skipped.
 */

import type { InvalidCredentialsError } from '@qauth-labs/shared-errors';

import { issuerTrustRejection } from '../trust/issuer-trust-rejection';

/**
 * Why one Verifiable Presentation was refused (#234).
 *
 * Every member is SERVER-SIDE ONLY. The mapping to the wire is total and
 * constant: all of them become the one refusal in
 * `trust/issuer-trust-rejection.ts`.
 *
 * - `unsupported-credential-format` — the Credential Format is unknown to QAuth
 *   or forbidden by the active `VerifierProfile`. Covers `mso_mdoc` until its
 *   adapter ships.
 * - `malformed-presentation` — structurally unusable: not the SD-JWT compact
 *   serialization, an undecodable JOSE segment, a missing `vct`/`iss`, an
 *   unsupported `_sd_alg`, or a credential type the DCQL query never asked for.
 * - `issuer-key-unresolvable` — no verification key could be obtained for the
 *   `iss` the credential claims (unknown issuer, ambiguous key set, a resolver
 *   that failed). Deliberately NOT the same as a bad signature: nothing was
 *   verified, so nothing was disproved either.
 * - `issuer-signature-invalid` — a key WAS resolved and the Issuer-signed JWS
 *   did not verify under it, or the validated identity could not be asserted.
 * - `credential-expired` / `credential-not-yet-valid` — the credential's own
 *   validity window (`exp` / `nbf`) excludes now.
 * - `disclosure-digest-mismatch` — a Disclosure did not hash to a digest present
 *   in the SD-JWT, a digest was claimed twice, or a Disclosure was altered.
 * - `holder-binding-invalid` — the Key Binding JWT is absent, unverifiable
 *   against the credential's `cnf` key, or carries the wrong `aud`, `nonce`,
 *   `sd_hash` or `iat`. One reason rather than four on purpose: they are all the
 *   same finding — this Presentation was not bound to this request by this
 *   holder — and splitting them would tempt a caller into reporting WHICH of our
 *   request parameters a probe got wrong.
 */
export type PresentationRejectionReason =
  | 'unsupported-credential-format'
  | 'malformed-presentation'
  | 'issuer-key-unresolvable'
  | 'issuer-signature-invalid'
  | 'credential-expired'
  | 'credential-not-yet-valid'
  | 'disclosure-digest-mismatch'
  | 'holder-binding-invalid';

/**
 * A refused Verifiable Presentation.
 *
 * Carries the precise outcome for the server and renders the single
 * non-enumerating error for the client. Never construct the client error
 * independently — going through {@link toClientError} is what keeps the two
 * bound together as the code evolves.
 */
export class PresentationValidationRejection extends Error {
  /** The distinct, SERVER-SIDE outcome. Never put this on the wire. */
  readonly reason: PresentationRejectionReason;

  /** Free-text server-side detail for logs. Never put this on the wire. */
  readonly detail: string;

  constructor(reason: PresentationRejectionReason, detail: string, options?: { cause?: unknown }) {
    super(`Verifiable Presentation rejected (${reason}): ${detail}`, options);
    this.name = 'PresentationValidationRejection';
    this.reason = reason;
    this.detail = detail;
    Object.setPrototypeOf(this, PresentationValidationRejection.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, PresentationValidationRejection);
    }
  }

  /**
   * The client-facing error: the SAME `InvalidCredentialsError` an untrusted
   * issuer produces (#236), with the same message, for every reason.
   *
   * That identity is the security property. A probing caller cannot tell an
   * expired credential from a forged one, nor either from a perfectly valid
   * credential whose issuer this realm does not trust.
   */
  toClientError(): InvalidCredentialsError {
    return issuerTrustRejection();
  }
}

/**
 * Build a rejection.
 *
 * A helper rather than bare `new` at ~30 call sites, so the reason and the
 * detail always travel together and no site is tempted to throw a plain `Error`
 * (which would escape a route's `catch` as a 500 — an oracle, since only some
 * inputs would produce it).
 *
 * @param reason - the server-side outcome.
 * @param detail - what actually went wrong, for the server log.
 * @param cause - the underlying error, when there was one.
 */
export function rejectPresentation(
  reason: PresentationRejectionReason,
  detail: string,
  cause?: unknown
): PresentationValidationRejection {
  return new PresentationValidationRejection(
    reason,
    detail,
    cause === undefined ? undefined : { cause }
  );
}

/**
 * Narrow an unknown thrown value to a {@link PresentationValidationRejection}.
 *
 * `instanceof` is sufficient here — unlike `ValidatedIssuer.isValidated`, this
 * type carries no authority, so there is nothing to forge. A caller uses it to
 * decide whether it already has a non-enumerating refusal or is holding an
 * unexpected fault that must NOT be converted into one silently.
 */
export function isPresentationValidationRejection(
  value: unknown
): value is PresentationValidationRejection {
  return value instanceof PresentationValidationRejection;
}
