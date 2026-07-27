/**
 * The presentation-validation CONTRACT (issue #234) — what validation consumes
 * ({@link PresentationValidationContext}) and what it produces
 * ({@link ValidatedCredential}).
 *
 * ## `ValidatedCredential` is not `VerifiedIdentity`, and the distance is the point
 *
 * A `VerifiedIdentity` (ADR-003) is an authentication result: the auth engine
 * upserts whatever `externalSub` it carries and mints a QAuth token for it, with
 * no provider-specific second guess. A {@link ValidatedCredential} is a
 * CRYPTOGRAPHIC FINDING and nothing more — "this credential was signed by this
 * issuer, these claims were selectively disclosed, and the holder proved
 * possession of the bound key against THIS request".
 *
 * Three things still stand between the two, and none of them is this issue's:
 *
 *  - **Issuer trust (#236).** {@link ValidatedCredential.issuer} is a
 *    `ValidatedIssuer`, which means "key resolution confirmed this identifier",
 *    NOT "this realm accepts credentials from it". A validly-signed credential
 *    from an issuer nobody trusts is a forgery with extra steps.
 *  - **Subject resolution (#300 / ADR-009).** There is no protocol-guaranteed
 *    stable wallet subject identifier, so nothing here answers "which account?".
 *  - **Revocation (#297).** {@link CredentialAssuranceSignal.statusChecked} is
 *    the literal `false` — see below.
 *
 * ## What is deliberately ABSENT from this type
 *
 * No subject identifier of any kind, and no holder key material. OID4VP 1.0
 * §15.5–§15.6 treat the issuer signature and the credential-bound public key as
 * LINKABILITY DEFECTS that wallets are expected to rotate away, and ADR-009
 * forbids keying an account on wallet cryptography. So the `cnf` key that proves
 * holder binding is CONSUMED during validation and then dropped — it is stripped
 * from {@link ValidatedCredential.claims} rather than merely left unused, because
 * a field that is present will eventually be read.
 *
 * The raw `iss` is stripped for the same reason in a different direction: the
 * issuer identity lives on {@link ValidatedCredential.issuer} as a nominally
 * typed `ValidatedIssuer`, and leaving a bare `iss` string in the claims would
 * hand a downstream caller something that LOOKS like an issuer identity but
 * carries none of #236's guarantees.
 */

import type { JwsAlgorithm } from '@qauth-labs/core-crypto';

import type {
  KeyStorageAssuranceEvidence,
  KeyStorageAssuranceGate,
} from '../attestation/key-storage-assurance';
import type { CredentialFormat } from '../profiles/verifier-profile.types';
import type { ValidatedIssuer } from '../trust/issuer-identity';
import type { IssuerKeyResolver } from './issuer-key-resolution';

/**
 * Default tolerance, in seconds, applied to every temporal comparison.
 *
 * Small and deliberate. A wallet and a Verifier are separate machines and a few
 * seconds of clock skew is normal; a minute of slack on an `exp` is not a
 * meaningful weakening, while zero tolerance turns ordinary NTP drift into
 * intermittent, unreproducible authentication failures.
 */
export const DEFAULT_PRESENTATION_CLOCK_TOLERANCE_SECONDS = 60;

/**
 * Default ceiling on the age of a Key Binding JWT.
 *
 * The KB-JWT is signed by the holder at presentation time, so its `iat` bounds
 * how long ago the holder actually approved this presentation. Five minutes
 * matches `DEFAULT_OID4VP_REQUEST_TTL_MS` — the request the presentation answers
 * cannot outlive its own request state, so a longer window here would be slack
 * that buys nothing while widening the replay surface if a `state` leaked.
 */
export const DEFAULT_KEY_BINDING_MAX_AGE_SECONDS = 300;

/**
 * Everything validation needs that does not come out of the credential itself.
 *
 * Every member is a BINDING that a Presentation must satisfy, or the policy that
 * decides what "satisfy" means. None of them has a default that could silently
 * disable a check: `clientId`, `nonce`, `signatureAlgorithms` and
 * `resolveIssuerKey` are all required, because a validator that "helpfully"
 * skipped the audience check when no audience was supplied would be the single
 * most dangerous line in this library.
 */
export interface PresentationValidationContext {
  /**
   * QAuth's OID4VP `client_id`, exactly as it appeared in the Authorization
   * Request. The Key Binding JWT's `aud` MUST equal it — this is what stops a
   * Presentation made to a different Verifier from being replayed at QAuth.
   *
   * MUST be non-empty; validation refuses the whole Presentation otherwise,
   * because an empty audience matches an empty `aud` and deletes the check.
   */
  readonly clientId: string;
  /**
   * The `nonce` from the redeemed request state (#233), VERBATIM. The Key
   * Binding JWT's `nonce` MUST equal it — this is what makes the Presentation
   * fresh and specific to this request (OID4VP 1.0 §14.1).
   *
   * MUST be non-empty, for the same reason as {@link clientId}.
   */
  readonly nonce: string;
  /**
   * JOSE algorithms accepted for the Issuer-signed JWS and the Key Binding JWT.
   *
   * A caller-supplied ALLOWLIST, never read from the token being verified: the
   * classic algorithm-confusion defence (RFC 9700). Must be non-empty. HAIP §7
   * pins `ES256`; a base-profile deployment issuing its own credentials may also
   * permit `EdDSA`.
   */
  readonly signatureAlgorithms: readonly JwsAlgorithm[];
  /** How to obtain the issuer's verification key — see {@link IssuerKeyResolver}. */
  readonly resolveIssuerKey: IssuerKeyResolver;
  /**
   * Credential Formats the active `VerifierProfile` permits.
   *
   * Re-checked at validation even though the intake (#233) already checked it,
   * because the two run at different times against a posture that may have
   * changed, and "the earlier layer checked it" is not a property this layer can
   * assert about itself.
   */
  readonly permittedFormats: readonly CredentialFormat[];
  /**
   * The active profile's key-storage-assurance posture and this deployment's
   * resolver for it (#308) — see
   * {@link import('../attestation/key-storage-assurance').keyStorageAssuranceGateFor}.
   *
   * Optional, and its absence means the `oid4vp-1.0-base` posture: key storage
   * is not evaluated and no conveyed signal is read. That is the honest default
   * for a field whose only other reading would be a profile this context does
   * not carry — every other profile-derived member here (`permittedFormats`,
   * `signatureAlgorithms`) is supplied by the caller from the resolved profile,
   * and this one is no different.
   *
   * Build it with `keyStorageAssuranceGateFor(profile, resolver)` rather than by
   * hand: that helper keeps the profile's posture even when no resolver is
   * provisioned, so a `required` profile with nothing wired refuses every
   * presentation instead of silently downgrading itself. A deployment is
   * additionally refused at BOOT by `assertKeyStorageAssuranceProvisioned`.
   */
  readonly keyStorageAssurance?: KeyStorageAssuranceGate;
  /** Clock skew tolerance; defaults to {@link DEFAULT_PRESENTATION_CLOCK_TOLERANCE_SECONDS}. */
  readonly clockToleranceSeconds?: number;
  /** KB-JWT age ceiling; defaults to {@link DEFAULT_KEY_BINDING_MAX_AGE_SECONDS}. */
  readonly keyBindingMaxAgeSeconds?: number;
  /** Reference time; defaults to now. Injectable so expiry behaviour is testable. */
  readonly now?: Date;
}

/**
 * The credential's own validity window, in epoch SECONDS (the JWT unit).
 *
 * Both members are optional because SD-JWT VC makes both optional. They are
 * reported rather than merely enforced so that a caller minting a session, an
 * attribute row (#235) or an `acr` claim (#237) can bound its own lifetime by
 * the credential's — an attribute asserted by a credential that expires tomorrow
 * should not outlive it.
 */
export interface CredentialValidityWindow {
  /** `nbf` — not valid before this instant. */
  readonly notBefore?: number;
  /** `exp` — not valid at or after this instant. */
  readonly expiresAt?: number;
  /** `iat` — when the issuer says it issued the credential. */
  readonly issuedAt?: number;
}

/**
 * The EVIDENCE an assurance decision is made from — not the decision.
 *
 * #234 must return an "assurance signal", and it must NOT return an
 * `AssuranceLevel`. The eIDAS Level of Assurance that eventually propagates as
 * `acr` (#237) is a property of the credential AND of the issuer that issued it
 * — a `high` LoA claim is only worth what the issuer behind it is worth, and
 * whether this realm accepts that issuer at all is #236's answer, taken AFTER
 * this object exists. Emitting a level here would mean deriving it before the
 * inputs are known, and every consumer would then read a guess as a verdict.
 *
 * So this records what was actually PROVEN, and lets the trust layer map it.
 */
export interface CredentialAssuranceSignal {
  /** The `vct` — which credential type the issuer asserts this is. */
  readonly credentialType: string;
  /** How the issuer's verification key was obtained (`x5c` vs issuer metadata). */
  readonly issuerKeyResolution: ValidatedIssuer['keyResolution'];
  /** Algorithm of the verified Issuer-signed JWS. */
  readonly issuerSignatureAlgorithm: JwsAlgorithm;
  /** Algorithm of the verified Key Binding JWT. */
  readonly keyBindingAlgorithm: JwsAlgorithm;
  /** How many Disclosures the holder chose to reveal. */
  readonly disclosedClaimCount: number;
  /**
   * What was established about WHERE the holder's private key lives (#308).
   *
   * Evidence, like everything else on this type — `'none'` under a profile that
   * does not evaluate key storage, and under one that does it is whatever a
   * conveyed key attestation or the transitive trusted-issuer path proved. A
   * profile REQUIRING assurance never produces a credential carrying `'none'`
   * here: validation refuses first.
   *
   * Required rather than optional so every producer must state it, and so #237
   * cannot read a missing field as "not applicable" when it means "nobody
   * looked". No holder key material is carried — the `cnf` key is compared
   * during resolution and dropped (OID4VP §15.5–§15.6, ADR-009).
   */
  readonly keyStorageAssurance: KeyStorageAssuranceEvidence;
  /**
   * Whether credential status (Token Status List, HAIP §6.1) was checked.
   *
   * Typed as the LITERAL `false`, not `boolean`. Revocation checking is #297, so
   * today no code path in this library can truthfully say otherwise — and the
   * literal type means none can even claim to. When #297 lands it widens this to
   * a union, which is a compile-time event every consumer sees, rather than a
   * silent flip from `false` to `true` that nobody reviews.
   */
  readonly statusChecked: false;
}

/**
 * One cryptographically validated Verifiable Presentation.
 *
 * Produced ONLY by a credential-format adapter's `validatePresentation`. The
 * existence of an instance means, and means exactly:
 *
 *  1. the Issuer-signed JWS verified under a key that key resolution bound to
 *     {@link issuer};
 *  2. every presented Disclosure hashed to a digest the issuer signed, none
 *     twice, and none was left unmatched;
 *  3. the credential's validity window includes now;
 *  4. the holder proved possession of the credential's bound key against THIS
 *     request's `nonce` and QAuth's `client_id`.
 *
 * It means nothing about trust, identity, account linkage or revocation.
 */
export interface ValidatedCredential {
  /** The DCQL Credential Query id this Presentation answered. */
  readonly queryId: string;
  /** The Credential Format whose adapter produced this. */
  readonly format: CredentialFormat;
  /** The credential type (`vct` for SD-JWT VC). */
  readonly credentialType: string;
  /**
   * The VALIDATED issuer identity, for #236 to make a trust decision about.
   *
   * Nominally typed: it cannot be forged from a raw `iss` string, and #236's
   * gate re-checks the brand at run time.
   */
  readonly issuer: ValidatedIssuer;
  /**
   * The disclosed claim set: always-present claims plus every claim the holder
   * chose to reveal, with the selective-disclosure machinery resolved away.
   *
   * Control and identity-linkage members are REMOVED — `_sd`, `_sd_alg`, `cnf`
   * and `iss` (see the module JSDoc). What remains is the credential's actual
   * assertions, for #235 to normalize into `user_attributes`.
   */
  readonly claims: Readonly<Record<string, unknown>>;
  /** The credential's own validity window. */
  readonly validity: CredentialValidityWindow;
  /** What was proven, for the assurance decision that happens later. */
  readonly assurance: CredentialAssuranceSignal;
}
