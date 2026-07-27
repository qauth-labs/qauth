/**
 * The CLAIM-EXTRACTION format boundary (issue #235, ADR-004).
 *
 * ## Why this is a second adapter seam and not a fourth method on the first
 *
 * `oid4vp/credential-format.ts` already carries a `CredentialFormatAdapter`, and
 * its module JSDoc closes with *"Do not add a fourth method that a caller could
 * reach around the registry to invoke."* That instruction is honoured here rather
 * than worked around: the three methods on that interface are the WIRE lifetime
 * of a format — build the DCQL query, structurally parse a `vp_token` entry,
 * cryptographically validate it. All three run before anything is known about a
 * person, and all three live in the protocol layer.
 *
 * Claim normalization runs AFTER validation, on the identity side of the seam,
 * and answers a different question: *given claims that are already proven, which
 * `user_attributes` rows do they mean?* Folding it into the protocol adapter
 * would make `oid4vp/` import the ADR-003 provider surface (`UserAttribute`) and
 * would put an identity mapping behind an interface whose other methods handle
 * attacker-supplied bytes. `oid4vp/safety-boundary.test.ts` asserts that no
 * module in `oid4vp/` so much as names `VerifiedIdentity`; this boundary is what
 * keeps that true while still giving claim mapping a per-format seat.
 *
 * ## Why the mapping MUST be per-format (issue #235, load-bearing)
 *
 * SD-JWT VC and ISO mdoc are not two encodings of one claim set. They use
 * DIFFERENT NAMES for the same attribute, and different structures:
 *
 * - The EUDI PID Rulebook's mdoc encoding uses the Table 1 data identifiers —
 *   `birth_date`, `nationality` — inside a namespace (`eu.europa.ec.eudi.pid.1`).
 * - Its SD-JWT VC encoding uses the OIDC-registered names instead. ADR-009's
 *   Finding 1 records the worked example from Rulebook §4.3 verbatim: `vct`,
 *   `given_name`, `family_name`, **`birthdate`**, `address`, **`nationalities`**,
 *   `sex`, `place_of_birth`, `cnf`, `issuing_authority`, `issuing_country`.
 *
 * `birth_date` versus `birthdate`; a singular `nationality` versus a
 * `nationalities` ARRAY. One shared code path would either miss half the
 * attributes of whichever format it was not written for, or accept both
 * vocabularies everywhere — which is worse, because it would let a credential in
 * one format be read through the other format's assumptions. Hence one adapter
 * per format, each speaking only its own vocabulary.
 *
 * ## Type-only, on purpose
 *
 * Mirrors `oid4vp/validated-credential.ts` and `providers/credential-provider.interface.ts`:
 * a consumer that depends on the CONTRACT should not thereby depend on the
 * SD-JWT VC implementation.
 *
 * @see docs/adr/004-wallet-agnostic-federation.md
 * @see docs/adr/002-identifier-abstraction.md
 */

import type { CredentialFormat } from '../profiles/verifier-profile.types';

/**
 * The narrow view of a validated credential a claim adapter is given.
 *
 * A structural SUBSET of `ValidatedCredential`, which satisfies it without a
 * cast. Narrow on purpose: an adapter that could see `ValidatedCredential.issuer`
 * could make a trust decision, and trust is #236's — decided once, before
 * normalization runs, never re-litigated per format. An adapter that could see
 * `assurance` could make #237's decision for the same wrong reason.
 *
 * `credentialType` is included even though the SD-JWT VC adapter does not read
 * it: an mdoc adapter maps NAMESPACED data elements, and the namespace is a
 * function of the doctype, so the seat has to exist or registering mdoc would
 * mean widening this interface — which is exactly the change
 * `credential-claim-adapters.mdoc-registration.test.ts` exists to catch.
 */
export interface CredentialClaimSet {
  /** The Credential Format the claims were read from. */
  readonly format: CredentialFormat;
  /** The `vct` (SD-JWT VC) or doctype (mdoc) the issuer asserted. */
  readonly credentialType: string;
  /**
   * The disclosed claims, with the format's selective-disclosure machinery
   * already resolved away and `_sd`, `_sd_alg`, `cnf` and `iss` stripped (#234).
   */
  readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * One credential claim, reduced to the `user_attributes` vocabulary.
 *
 * Deliberately NOT a `UserAttribute`: an adapter decides what a claim MEANS, not
 * how much QAuth trusts it. `source`, `verified` and `expiresAt` are properties
 * of the credential and of the provider, identical for every format, and are
 * applied once in `providers/wallet.provider.ts`. An adapter that could set them
 * would be an adapter that could mark its own output unverified — or verified.
 */
export interface NormalizedCredentialClaim {
  /**
   * `user_attributes.attr_key` — the CANONICAL key, after the per-format name
   * mapping. This is the value #229's trust ordering compares across sources, so
   * a wallet-sourced email must land on exactly the key `PasswordProvider` uses
   * (`EMAIL_ATTR_KEY`) or the two never meet and the trust order does nothing.
   */
  readonly attrKey: string;
  /** `user_attributes.attr_value` — non-empty; the column is `text NOT NULL`. */
  readonly attrValue: string;
}

/**
 * A credential format whose validated claims QAuth can normalize.
 *
 * One method, and it is PURE: no I/O, no clock, no configuration. Everything it
 * needs is already inside the {@link ValidatedCredential}, which is what makes
 * "adding `mso_mdoc` is a registration" checkable rather than aspirational —
 * see `claims/credential-claim-adapters.mdoc-registration.test.ts`.
 */
export interface CredentialClaimAdapter {
  /** The Credential Format this adapter speaks. */
  readonly format: CredentialFormat;
  /**
   * Map a validated credential's disclosed claims onto canonical attribute keys.
   *
   * MUST be fail-closed: a claim the adapter does not recognise produces no row.
   * A wallet attribute is an assertion QAuth will later emit downstream (the
   * `email` key is already read by `helpers/email-claims.ts` and lands in ID
   * tokens), so an open mapping would let any trusted issuer mint arbitrary
   * claim surface.
   *
   * MUST NOT throw for credential content — a credential carrying nothing
   * mappable yields an empty list, which is a legitimate outcome (an
   * age-attestation EAA asserts no identity attribute at all).
   *
   * @param claimSet - claims from a credential that validated (#234) and whose
   * issuer this realm trusts (#236). Both gates run BEFORE this.
   * @returns the normalized claims, in a deterministic order.
   */
  normalizeClaims(claimSet: CredentialClaimSet): readonly NormalizedCredentialClaim[];
}

/**
 * A table of claim adapters, keyed by Credential Format.
 *
 * `Partial` for the same reason `CredentialFormatAdapterRegistry` is: a format a
 * profile PERMITS but QAuth cannot normalize must be refused, never stubbed. A
 * stub returning `[]` would be indistinguishable from a credential that
 * disclosed nothing, which is silent claim loss.
 */
export type CredentialClaimAdapterRegistry = Readonly<
  Partial<Record<CredentialFormat, CredentialClaimAdapter>>
>;
