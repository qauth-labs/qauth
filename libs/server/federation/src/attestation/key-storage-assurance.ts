import type { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import type { JWK } from 'jose';

import type { CapabilityPosture, VerifierProfile } from '../profiles/verifier-profile.types';
import type { ValidatedIssuer } from '../trust/issuer-identity';
import {
  type AttackPotentialResistance,
  meetsAttackPotential,
  reduceAttackPotentialClaim,
} from './attack-potential';
import { type KeyStorageAttestingIssuers, NO_ATTESTING_ISSUERS } from './attesting-issuers';
import {
  type KeyAttestationTrustAnchors,
  NO_KEY_ATTESTATION_TRUST_ANCHORS,
  validateKeyAttestation,
} from './key-attestation';
import {
  keyStorageAssuranceRejection,
  type KeyStorageAssuranceRejectionReason,
} from './key-storage-assurance-rejection';

/**
 * Key-storage assurance resolution — the #308 gate (HAIP §9.2, §4.5.1).
 *
 * ## The three-way distinction this module must never blur
 *
 * | Concern | Question | Owner |
 * |---|---|---|
 * | Holder binding (KB-JWT / `cnf`) | Does the presenter control the key bound to this credential, right now? | #234 |
 * | Issuer trust | Is the party that ISSUED this credential trusted by this realm? | #236 |
 * | **Key storage (here)** | Is that key generated and STORED in a certified secure cryptographic device, at a required attack-potential level? | #308 |
 *
 * This gate is layered ON TOP of the first two. It never repeats the possession
 * check, it is not the issuer-identity check, and it never substitutes for
 * either: a presentation that clears this gate and fails holder binding is
 * refused by #234 before this runs, and one that clears this gate from an
 * untrusted issuer is refused by #236 afterwards. Nothing here emits a
 * `VerifiedIdentity`, and nothing here relaxes a check anyone else makes.
 *
 * ## Where assurance can come from, in order
 *
 * 1. **A conveyed OID4VCI Appendix D key attestation** — validated in full by
 *    `key-attestation.ts`, including the binding to the credential's `cnf` key.
 *    The strongest and rarest source; see that module for why a Verifier is not
 *    generally given one.
 * 2. **An issuer-asserted key-storage claim in the credential** — honoured only
 *    for an issuer the operator recorded as attesting key storage, and CAPPED at
 *    the level the operator recorded. An issuer may say it uses weaker storage
 *    than the operator expected; it may not promote itself.
 * 3. **The transitive path** — the credential's validated issuer is a HAIP
 *    issuance chain the operator recorded as validating key attestations per
 *    §4.5.1. QAuth does not re-derive WSCD assurance at the presentation seam;
 *    it relies on that issuer having done the work at issuance. See
 *    `attesting-issuers.ts` for the reasoning, which is the substance of #308.
 *
 * A conveyed attestation that is present but does NOT validate is a refusal, not
 * an absence — #308: *"Where nothing is conveyed and the profile is `haip-1.0`,
 * fall through to the transitive path above."* Nothing conveyed falls through;
 * something conveyed and broken does not.
 *
 * ## Profile posture, and what `forbidden` means here
 *
 * `VerifierProfile.keyStorageAssurance` decides whether any of this runs:
 *
 * - `required` (`haip-1.0`) — assurance MUST be established and MUST meet the
 *   profile's floor, or the presentation is refused. There is no permissive
 *   fallback and no "accepted because it parsed".
 * - `permitted` — assurance is evaluated and reported. A conveyed attestation
 *   still has to be valid; a level below any floor is not enforced, because none
 *   is required.
 * - `forbidden` (`oid4vp-1.0-base`) — the capability is not part of the profile.
 *   The extractor is not even invoked, so a conveyed signal cannot influence
 *   anything, and the resolved value is always {@link NO_KEY_STORAGE_ASSURANCE}.
 *   `CapabilityPosture` documents `forbidden` as "unreachable, not merely
 *   undefaulted": what is made unreachable is the SIGNAL's ability to raise
 *   assurance, not the credential's ability to be accepted. Refusing an
 *   otherwise-valid base-profile credential because its issuer chose to include
 *   extra assurance would be a regression dressed as strictness — the base
 *   profile must be unaffected by this issue entirely.
 */

/** How much QAuth knows about WHERE the holder's private key lives. */
export type KeyStorageAssurance =
  /**
   * Nothing established. Either the profile does not evaluate key storage, or
   * it does and no source produced anything — in which case a `required`
   * posture has already refused the presentation and this value never reaches a
   * consumer as an accepted outcome.
   */
  | 'none'
  /**
   * Inherited from the ISSUER: the credential comes from an issuance chain the
   * operator recorded as validating key attestations per HAIP §4.5.1. QAuth did
   * not see an attestation; it relies on the issuer having required one.
   */
  | 'issuer-attested'
  /**
   * Established DIRECTLY: an Appendix D key attestation was conveyed into the
   * presentation, verified to an anchored chain, and attests the very key this
   * credential is bound to.
   */
  | 'key-attested';

/**
 * What key-storage resolution established — evidence, never a decision.
 *
 * The same discipline `CredentialAssuranceSignal` follows: this reports what was
 * PROVEN about the holder's key, and the eIDAS Level of Assurance that
 * eventually propagates as `acr` is derived from it by #237, together with the
 * issuer trust decision it cannot see from here.
 */
export interface KeyStorageAssuranceEvidence {
  /** Which of the three sources (if any) established anything. */
  readonly assurance: KeyStorageAssurance;
  /** The attack potential the key STORAGE resists, when a source stated one. */
  readonly keyStorage?: AttackPotentialResistance;
  /**
   * The attack potential the USER AUTHENTICATION gating the key resists, when an
   * attestation stated one. Reported separately and never merged into
   * {@link keyStorage}: a certified enclave behind no PIN and a software key
   * behind a certified biometric are different propositions.
   */
  readonly userAuthentication?: AttackPotentialResistance;
}

/**
 * The evidence value meaning "nothing was established".
 *
 * A named constant rather than an inline literal so "we did not evaluate" and
 * "we evaluated and found nothing" are the same object, and neither can be
 * mistaken for a level.
 */
export const NO_KEY_STORAGE_ASSURANCE: KeyStorageAssuranceEvidence = Object.freeze({
  assurance: 'none',
});

/**
 * Whether key-storage evidence clears a floor.
 *
 * The unit #237 wires in. It answers ONLY the key-storage question — it does not
 * know about issuers, credential types or eIDAS levels, and deriving one from it
 * is #237's job. Exported so that "a `haip-1.0` presentation lacking the
 * required key-storage assurance MUST NOT yield a `high` assurance level" is one
 * call rather than a re-implementation of the comparison.
 *
 * Fail-CLOSED throughout: `assurance: 'none'` never clears a floor, an absent
 * level never clears one, and an unrecognised floor clears nothing (see
 * {@link meetsAttackPotential}).
 *
 * @param evidence - what resolution established.
 * @param minimum - the floor being tested.
 * @returns whether the evidence meets it.
 */
export function keyStorageAssuranceMeets(
  evidence: KeyStorageAssuranceEvidence,
  minimum: AttackPotentialResistance
): boolean {
  if (evidence.assurance === 'none') return false;
  return meetsAttackPotential(evidence.keyStorage, minimum);
}

/**
 * The profile's key-storage posture, extracted as data.
 *
 * Carried separately from the profile so the resolver reads a policy rather than
 * a `VerifierProfile` — which keeps it usable by #237 over a credential some
 * other adapter validated, and keeps profiles DATA rather than something this
 * module branches on by id.
 */
export interface KeyStorageAssurancePolicy {
  readonly posture: CapabilityPosture;
  /**
   * The floor a `required` posture enforces. Absent means "any established
   * assurance satisfies the requirement", which is a coherent posture for an
   * ecosystem that mandates a WSCD without grading it.
   */
  readonly minimumAttackPotential?: AttackPotentialResistance;
}

/** The policy meaning "this profile does not evaluate key storage". */
const NOT_EVALUATED_POLICY: KeyStorageAssurancePolicy = Object.freeze({ posture: 'forbidden' });

/**
 * Read a profile's key-storage policy.
 *
 * No profile is named here: adding a future profile must require editing the
 * profile table and nothing else (#299 acceptance criterion), so this reads the
 * declared capability and lets the data decide.
 *
 * @param profile - the active verifier profile, or nothing at all. `undefined`
 * yields the not-evaluated policy rather than throwing: a caller with no profile
 * has already been refused a wallet flow entirely (`resolveVerifierProfile`), so
 * the only honest answer here is "nothing to evaluate".
 */
export function keyStorageAssurancePolicyOf(
  profile: VerifierProfile | null | undefined
): KeyStorageAssurancePolicy {
  if (profile === null || profile === undefined) return NOT_EVALUATED_POLICY;

  return Object.freeze({
    posture: profile.keyStorageAssurance,
    ...(profile.minimumKeyStorageAttackPotential === undefined
      ? {}
      : { minimumAttackPotential: profile.minimumKeyStorageAttackPotential }),
  });
}

/**
 * A key-storage assurance signal an ecosystem conveyed into the presentation.
 *
 * Two shapes, because two things are conveyable and they are validated
 * completely differently. Neither is trusted at the point it is extracted.
 */
export type ConveyedKeyStorageSignal =
  /** A compact-JWS OID4VCI Appendix D key attestation, entirely unverified. */
  | { readonly kind: 'key-attestation'; readonly attestation: unknown }
  /** An issuer-asserted key-storage level carried as a credential claim. */
  | { readonly kind: 'credential-claim'; readonly keyStorage: unknown };

/** What an extractor is given. */
export interface ConveyedSignalSource {
  /**
   * The credential's claims as #234 resolved them, INCLUDING `cnf` and `iss` —
   * i.e. before the stripping that produces `ValidatedCredential.claims`. An
   * assurance signal may legitimately live inside `cnf`, which the public claim
   * set no longer carries.
   */
  readonly claims: Readonly<Record<string, unknown>>;
}

/**
 * How a deployment finds an assurance signal in a presentation.
 *
 * A seam rather than a fixed rule, and deliberately so. No specification places
 * a key attestation in a PRESENTATION — HAIP puts it on the issuance path — so
 * any location is an ecosystem convention, and hard-coding one convention as if
 * it were the standard is the "derivation, not invention" mistake #308 exists to
 * avoid. QAuth ships {@link defaultConveyedSignalExtractor} for the two
 * conventional locations and lets an ecosystem replace it.
 *
 * Must not throw. An extractor that does is CONTAINED by the resolver and its
 * failure treated as "nothing conveyed", so a broken extractor cannot turn a
 * contained refusal into a 500 — but containment is a backstop, not a licence.
 */
export type ConveyedKeyStorageSignalExtractor = (
  source: ConveyedSignalSource
) => ConveyedKeyStorageSignal | undefined;

/**
 * The member an Appendix D key attestation is conveyed under.
 *
 * `key_attestation` is the name OID4VCI already gives it in the `jwt` proof
 * type's JOSE header, so an ecosystem surfacing one to a Verifier is
 * overwhelmingly likely to reuse the name rather than coin another.
 */
export const CONVEYED_KEY_ATTESTATION_MEMBER = 'key_attestation';

/**
 * The credential claim an issuer asserts key storage under.
 *
 * `key_storage` matches Appendix D's own claim name and its §D.2 value space, so
 * an issuer stating in a credential what it validated at issuance states it in
 * the same vocabulary the attestation would have used.
 */
export const CONVEYED_KEY_STORAGE_CLAIM = 'key_storage';

/** Reject anything that is not a plain JSON object. */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/**
 * The shipped extractor: `cnf.key_attestation` first, then a `key_storage` claim.
 *
 * The attestation wins when both are present, because it is the one QAuth can
 * verify for itself. Preferring the issuer's word over an artifact carrying its
 * own proof would be strictly weaker, and would let an issuer's claim mask an
 * attestation that would have been REJECTED — turning a refusal into an
 * acceptance, which is the wrong direction for a precedence rule to fail in.
 *
 * @param source - the credential's resolved claims.
 * @returns the conveyed signal, or `undefined` when the presentation carries
 * none — the ordinary case, which falls through to the transitive path.
 */
export function defaultConveyedSignalExtractor(
  source: ConveyedSignalSource
): ConveyedKeyStorageSignal | undefined {
  const confirmation = source.claims['cnf'];

  if (isRecord(confirmation) && confirmation[CONVEYED_KEY_ATTESTATION_MEMBER] !== undefined) {
    return { kind: 'key-attestation', attestation: confirmation[CONVEYED_KEY_ATTESTATION_MEMBER] };
  }

  const claimed = source.claims[CONVEYED_KEY_STORAGE_CLAIM];
  if (claimed !== undefined) return { kind: 'credential-claim', keyStorage: claimed };

  return undefined;
}

/** What the gate is asked about one credential. */
export interface KeyStorageAssuranceInput {
  /**
   * The credential's validated issuer (#234). Used for the transitive path, and
   * nothing else — this gate makes no trust decision about it, which remains
   * #236's and runs separately.
   */
  readonly issuer: ValidatedIssuer;
  /**
   * The credential's holder-binding key (`cnf.jwk`).
   *
   * Compared against an attestation's `attested_keys` and then dropped. Never
   * returned, logged or persisted: OID4VP §15.5–§15.6 and ADR-009.
   */
  readonly confirmationJwk: JWK;
  /** The credential's resolved claims, `cnf`/`iss` included. */
  readonly claims: Readonly<Record<string, unknown>>;
  /** Reference time; defaults to now. Injectable so expiry is testable. */
  readonly now?: Date;
}

/** The decision the gate reached. */
export type KeyStorageAssuranceDecision =
  | { readonly outcome: 'accepted'; readonly evidence: KeyStorageAssuranceEvidence }
  | { readonly outcome: 'rejected'; readonly reason: KeyStorageAssuranceRejectionReason };

/** The gate #234 (and #237) calls. */
export interface KeyStorageAssuranceResolver {
  /**
   * Decide, without throwing.
   *
   * @param input - the credential's issuer, holder key and claims.
   * @param policy - the active profile's posture.
   */
  resolveKeyStorageAssurance(
    input: KeyStorageAssuranceInput,
    policy: KeyStorageAssurancePolicy
  ): Promise<KeyStorageAssuranceDecision>;

  /**
   * Assert the profile's key-storage requirement is met, throwing the single
   * non-enumerating refusal otherwise.
   *
   * Throws rather than returning a value for the same reason
   * `assertIssuerTrusted` does: a caller must not be able to proceed by ignoring
   * the result.
   *
   * @throws InvalidCredentialsError whenever the requirement is not positively
   * met.
   */
  assertKeyStorageAssurance(
    input: KeyStorageAssuranceInput,
    policy: KeyStorageAssurancePolicy
  ): Promise<KeyStorageAssuranceEvidence>;
}

/** Wiring for {@link createKeyStorageAssuranceResolver}. */
export interface KeyStorageAssuranceResolverConfig {
  /**
   * Which issuance chains the operator recorded as attesting key storage.
   * Defaults to none, so an unconfigured deployment establishes nothing — and a
   * `required` profile therefore refuses every presentation.
   */
  readonly attestingIssuers?: KeyStorageAttestingIssuers;
  /**
   * Anchors a conveyed Appendix D attestation's `x5c` chain must terminate at.
   *
   * A DIFFERENT anchor set from the status-list anchors (#297): these are wallet
   * provider CAs. Defaults to none, which leaves the DIRECT path unprovisioned —
   * a conveyed attestation is then SKIPPED rather than refused, and the
   * credential falls through to the transitive path. See `establish` for why
   * skipping is the fail-closed reading and refusing was not.
   */
  readonly keyAttestationAnchors?: KeyAttestationTrustAnchors;
  /** How to find a conveyed signal; defaults to {@link defaultConveyedSignalExtractor}. */
  readonly extractConveyedSignal?: ConveyedKeyStorageSignalExtractor;
  /** Clock skew tolerance in seconds applied to a conveyed attestation. */
  readonly clockToleranceSeconds?: number;
}

/**
 * Both halves of what the presentation seam needs: what the profile REQUIRES and
 * what this deployment can ESTABLISH.
 *
 * One object rather than two context fields so a caller cannot supply a policy
 * without a resolver, or a resolver without the policy it must be read against —
 * either of which would silently disable the gate.
 */
export interface KeyStorageAssuranceGate {
  readonly policy: KeyStorageAssurancePolicy;
  readonly resolver: KeyStorageAssuranceResolver;
}

/**
 * Build the gate for a profile.
 *
 * Fail-CLOSED when no resolver is supplied: the gate keeps the profile's
 * posture and gets {@link DENY_ALL_KEY_STORAGE_ASSURANCE_RESOLVER}, so a
 * `required` profile with nothing wired refuses every presentation rather than
 * quietly downgrading itself to `forbidden`. That is the whole point of building
 * the gate from the profile instead of from the wiring.
 *
 * @param profile - the active verifier profile.
 * @param resolver - this deployment's resolver, when one is provisioned.
 */
export function keyStorageAssuranceGateFor(
  profile: VerifierProfile | null | undefined,
  resolver?: KeyStorageAssuranceResolver
): KeyStorageAssuranceGate {
  return Object.freeze({
    policy: keyStorageAssurancePolicyOf(profile),
    resolver: resolver ?? DENY_ALL_KEY_STORAGE_ASSURANCE_RESOLVER,
  });
}

/**
 * What a deployment has provisioned for key-storage assurance, in the terms the
 * BOOT gate reads it in (#308/#379).
 *
 * A record rather than a boolean, for the reason `CredentialStatusProvisioning`
 * is one next door: the refusal has to name WHAT is wrong, and "nothing is
 * recorded" and "what is recorded cannot reach this profile's floor" are
 * different mistakes with different fixes. A boolean could express only the
 * first, which is how the second one used to boot.
 */
export interface KeyStorageAssuranceProvisioning {
  /**
   * The strongest §D.2 grade the attesting-issuer registry records — the
   * TRANSITIVE path — or `undefined` when it records nothing readable.
   *
   * Build it with `strongestAttestedKeyStorage` from the configured entries.
   * The strongest rather than the weakest, because the gate asks whether the
   * deployment can clear the floor for ANY ecosystem it recorded; see that
   * function for why.
   */
  readonly strongestAttestedKeyStorage?: AttackPotentialResistance;
  /**
   * Whether the deployment holds key-attestation trust anchors — the DIRECT
   * path.
   *
   * Unqualified by a grade on purpose: a conveyed Appendix D attestation states
   * its own grade, so anchors can establish any floor a profile declares and
   * the gate cannot rule them out in advance. `false` until an operator
   * configuration surface for wallet-provider anchors exists (#379).
   */
  readonly hasKeyAttestationAnchors?: boolean;
}

/**
 * The provisioning meaning "nothing at all", and the gate's fail-closed default.
 *
 * A frozen singleton for the same reason `NO_ATTESTING_ISSUERS` is one:
 * "we could not work out what this deployment provisioned" and "this deployment
 * provisioned nothing" must be the same value, not two branches one of which
 * might be forgotten.
 */
export const NO_KEY_STORAGE_ASSURANCE_PROVISIONING: KeyStorageAssuranceProvisioning = Object.freeze(
  {}
);

/**
 * Refuse, at BOOT, a profile that requires key-storage assurance this deployment
 * cannot establish (#308).
 *
 * The counterpart of `assertProfileWithinCryptoCapabilities`: a profile
 * declaring `keyStorageAssurance: 'required'` is a mandate, and a mandate no
 * code can satisfy is a deployment that would accept a wallet request and then
 * reject every single presentation. An operator must learn that at startup, not
 * from a 100% login-failure rate.
 *
 * ## The floor is part of the mandate
 *
 * A profile requiring assurance almost always requires it AT A LEVEL —
 * `haip-1.0` declares `minimumKeyStorageAttackPotential: 'iso_18045_high'` — and
 * `resolveKeyStorageAssurance` enforces that floor on every presentation. So a
 * deployment whose registry records only `iso_18045_basic` issuers has
 * provisioned something and still cannot satisfy the mandate: it boots, accepts
 * wallet requests, and refuses every presentation with
 * `attack-potential-below-minimum`. That is the same 100%-failure outcome as
 * provisioning nothing, reached by a different route, and this gate has to catch
 * both or it catches neither.
 *
 * The DIRECT path is exempt from the comparison, not from the gate: a conveyed
 * attestation states its own grade, so anchors can clear any floor and no
 * boot-time prediction is possible or needed.
 *
 * No profile is named: this reads the declared capability, so a future profile
 * requiring key-storage assurance is gated with no edit here.
 *
 * @param profile - the profile the deployment selected.
 * @param provisioned - what the operator provisioned for the transitive path (an
 * attesting-issuer registry) and the direct path (key-attestation trust
 * anchors). Defaults to {@link NO_KEY_STORAGE_ASSURANCE_PROVISIONING}: a caller
 * that forgets to thread it through fails closed rather than sails past, exactly
 * as `assertPrefixProvisioned` does for verifier material.
 * @throws Error when the profile requires assurance this deployment cannot
 * establish, naming which of the two ways it cannot.
 */
export function assertKeyStorageAssuranceProvisioned(
  profile: VerifierProfile,
  provisioned: KeyStorageAssuranceProvisioning = NO_KEY_STORAGE_ASSURANCE_PROVISIONING
): void {
  if (profile.keyStorageAssurance !== 'required') return;

  // Defensive rather than decorative: the value crosses a package boundary from
  // configuration parsing, and an unreadable one must land on "provisioned
  // nothing" rather than throw a TypeError out of a boot gate.
  const supplied =
    provisioned !== null && typeof provisioned === 'object'
      ? provisioned
      : NO_KEY_STORAGE_ASSURANCE_PROVISIONING;

  if (supplied.hasKeyAttestationAnchors === true) return;

  const recorded = supplied.strongestAttestedKeyStorage;

  if (recorded === undefined) {
    throw new Error(
      `Verifier profile '${profile.id}' requires key-storage assurance for every presentation (HAIP §4.5.1, #308), and this deployment has provisioned neither an attesting-issuer registry nor key-attestation trust anchors. Refusing to start rather than accepting wallet requests and then rejecting every presentation for assurance nothing here can establish.`
    );
  }

  const floor = profile.minimumKeyStorageAttackPotential;
  if (floor === undefined || meetsAttackPotential(recorded, floor)) return;

  throw new Error(
    `Verifier profile '${profile.id}' requires key-storage assurance at '${floor}' or stronger (OID4VCI Appendix D §D.2, #308), and the strongest level any issuer in OID4VP_ATTESTING_ISSUERS is recorded as attesting is '${recorded}'. Every presentation would be refused for attack potential below the profile's minimum, so this is refused at startup instead. Record an issuer that attests at '${floor}', or select a profile whose floor this deployment can meet.`
  );
}

/**
 * Build a key-storage assurance resolver (#308).
 *
 * @param config - see {@link KeyStorageAssuranceResolverConfig}.
 * @returns a resolver; safe to share across requests and concurrency-safe.
 */
export function createKeyStorageAssuranceResolver(
  config: KeyStorageAssuranceResolverConfig = {}
): KeyStorageAssuranceResolver {
  const attestingIssuers: KeyStorageAttestingIssuers =
    config.attestingIssuers ?? NO_ATTESTING_ISSUERS;
  const anchors: KeyAttestationTrustAnchors =
    config.keyAttestationAnchors ?? NO_KEY_ATTESTATION_TRUST_ANCHORS;
  const extract: ConveyedKeyStorageSignalExtractor =
    config.extractConveyedSignal ?? defaultConveyedSignalExtractor;

  /**
   * What the operator recorded about this issuer.
   *
   * The backend contract says it must not throw; containing a throw is the
   * fail-closed reading, and matches how `assertIssuerTrusted` contains a
   * TrustRegistry backend. A registry that cannot answer has recorded nothing.
   */
  const recordedFor = (issuer: ValidatedIssuer): AttackPotentialResistance | undefined => {
    try {
      return attestingIssuers.attestedKeyStorage(issuer);
    } catch {
      return undefined;
    }
  };

  /** Run the extractor without letting a broken one become the fault. */
  const conveyedSignal = (
    claims: Readonly<Record<string, unknown>>
  ): ConveyedKeyStorageSignal | undefined => {
    try {
      return extract({ claims });
    } catch {
      return undefined;
    }
  };

  const establish = async (
    input: KeyStorageAssuranceInput
  ): Promise<KeyStorageAssuranceDecision> => {
    const signal = conveyedSignal(input.claims);
    const recorded = recordedFor(input.issuer);

    // The DIRECT path is only ATTEMPTED where it can reach a verdict. With no
    // wallet-provider anchors configured there is nothing to anchor an `x5c`
    // chain against, so `validateKeyAttestation` refuses every attestation with
    // `attestation-chain-unanchored` — a verdict about THIS DEPLOYMENT's
    // configuration wearing the vocabulary of a verdict about the attestation.
    //
    // Read as a rejection it inverted the gate. A wallet that conveys a §9.2
    // attestation — the more conformant wallet, doing the more helpful thing —
    // was refused outright, while the same wallet omitting it sailed through the
    // transitive path below. Since the direct path has no configuration surface
    // yet (#379), that is EVERY deployment: recording an attesting issuer and
    // then meeting a wallet that attests would have failed 100% of its logins.
    //
    // Skipping is not a weakening. It grants exactly what the credential would
    // have been worth with no attestation conveyed at all — the operator's
    // recorded transitive claim, capped at what they recorded — and a forged
    // attestation buys its bearer nothing it did not already have. The moment
    // anchors ARE configured the branch is taken again and a failure to anchor
    // becomes what the vocabulary says it is: a forgery signal, refused.
    if (signal?.kind === 'key-attestation' && anchors.size > 0) {
      const validation = await validateKeyAttestation({
        attestation: signal.attestation,
        confirmationJwk: input.confirmationJwk,
        anchors,
        now: input.now ?? new Date(),
        ...(config.clockToleranceSeconds === undefined
          ? {}
          : { clockToleranceSeconds: config.clockToleranceSeconds }),
      });

      if (validation.outcome === 'rejected') {
        return { outcome: 'rejected', reason: validation.reason };
      }

      return {
        outcome: 'accepted',
        evidence: Object.freeze({
          assurance: 'key-attested',
          ...(validation.attestation.keyStorage === undefined
            ? {}
            : { keyStorage: validation.attestation.keyStorage }),
          ...(validation.attestation.userAuthentication === undefined
            ? {}
            : { userAuthentication: validation.attestation.userAuthentication }),
        }),
      };
    }

    // Everything from here depends on the operator having recorded this issuer.
    // Without that record there is no basis for believing anything about the
    // holder's key, so an issuer-asserted claim is worth exactly nothing — and
    // so is an attestation this deployment provisioned no way to evaluate.
    if (recorded === undefined) {
      return { outcome: 'rejected', reason: 'issuer-does-not-attest-key-storage' };
    }

    if (signal?.kind === 'credential-claim') {
      // Read through the same list reduction an attestation's claim goes
      // through — a list resists its WEAKEST member — and then CAPPED at what
      // the operator recorded. An issuer may report weaker storage for a
      // particular credential (a batch minted before a hardware rollout, say),
      // and must not be able to report stronger, or every recorded issuer could
      // grant itself any level it liked.
      //
      // An unreadable or unrecognised claim reduces to `undefined` and falls
      // back to the recorded level: it is the same situation as no claim at all,
      // and must not clear anything on its own.
      const claimed = reduceAttackPotentialClaim(signal.keyStorage);
      const effective =
        claimed !== undefined && meetsAttackPotential(recorded, claimed) ? claimed : recorded;

      return {
        outcome: 'accepted',
        evidence: Object.freeze({ assurance: 'issuer-attested', keyStorage: effective }),
      };
    }

    // Reached by a credential conveying no signal at all, and by one whose
    // key attestation was skipped above. Both get the recorded transitive claim
    // and nothing more: an attestation nobody could evaluate adds no grade, so
    // it cannot raise the level, and `assurance: 'issuer-attested'` says
    // truthfully which source the answer came from.
    return {
      outcome: 'accepted',
      evidence: Object.freeze({ assurance: 'issuer-attested', keyStorage: recorded }),
    };
  };

  const resolveKeyStorageAssurance = async (
    input: KeyStorageAssuranceInput,
    policy: KeyStorageAssurancePolicy
  ): Promise<KeyStorageAssuranceDecision> => {
    // The extractor is not reached at all under `forbidden`. See the module
    // JSDoc: what the posture makes unreachable is the SIGNAL, not the
    // credential.
    if (policy.posture === 'forbidden') {
      return { outcome: 'accepted', evidence: NO_KEY_STORAGE_ASSURANCE };
    }

    const decision = await establish(input);

    if (policy.posture === 'permitted') {
      // A conveyed attestation still has to be valid — a rejection above is a
      // forgery attempt, not an absence — but "this issuer is not recorded as
      // attesting" is simply an absence, and a profile that merely permits
      // assurance must accept a credential that carries none.
      if (
        decision.outcome === 'rejected' &&
        decision.reason === 'issuer-does-not-attest-key-storage'
      ) {
        return { outcome: 'accepted', evidence: NO_KEY_STORAGE_ASSURANCE };
      }
      return decision;
    }

    if (decision.outcome === 'rejected') {
      return decision.reason === 'issuer-does-not-attest-key-storage'
        ? { outcome: 'rejected', reason: 'assurance-required-but-absent' }
        : decision;
    }

    if (decision.evidence.assurance === 'none') {
      return { outcome: 'rejected', reason: 'assurance-required-but-absent' };
    }

    if (
      policy.minimumAttackPotential !== undefined &&
      !keyStorageAssuranceMeets(decision.evidence, policy.minimumAttackPotential)
    ) {
      return { outcome: 'rejected', reason: 'attack-potential-below-minimum' };
    }

    return decision;
  };

  return {
    resolveKeyStorageAssurance,
    async assertKeyStorageAssurance(
      input: KeyStorageAssuranceInput,
      policy: KeyStorageAssurancePolicy
    ): Promise<KeyStorageAssuranceEvidence> {
      const decision = await resolveKeyStorageAssurance(input, policy);
      if (decision.outcome !== 'accepted') {
        const rejection: InvalidCredentialsError = keyStorageAssuranceRejection(decision.reason);
        throw rejection;
      }
      return decision.evidence;
    },
  };
}

/**
 * A resolver that establishes nothing.
 *
 * The value an unwired deployment should hold, so "key-storage assurance is not
 * configured" is an object that fails closed rather than a `null` a call site
 * might skip past — the same role `DENY_ALL_TRUST_REGISTRY` and
 * `DENY_ALL_CREDENTIAL_STATUS_CHECKER` play for their gates. Under a `forbidden`
 * posture it still accepts, because that posture asks nothing of it.
 *
 * Built from {@link createKeyStorageAssuranceResolver} with no configuration
 * rather than hand-written, so it cannot drift into behaving differently from a
 * real resolver whose registries happen to be empty.
 */
export const DENY_ALL_KEY_STORAGE_ASSURANCE_RESOLVER: KeyStorageAssuranceResolver =
  createKeyStorageAssuranceResolver();
