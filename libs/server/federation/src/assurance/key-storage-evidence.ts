import {
  type AttackPotentialResistance,
  HIGHEST_ATTACK_POTENTIAL_RESISTANCE,
  isAttackPotentialResistance,
  meetsAttackPotential,
} from '../attestation/attack-potential';
import type {
  KeyStorageAssurance,
  KeyStorageAssuranceEvidence,
} from '../attestation/key-storage-assurance';
import type { AssuredKeyStorage } from './credential-assurance';

/**
 * The ONE translation from #308's key-storage evidence into #237's eIDAS
 * key-storage vocabulary (issue #379, ADR-010 §5, decided 2026-07-28).
 *
 * ## Why a translation exists at all
 *
 * The two sides were designed apart, deliberately, and this module is the seam —
 * not a rename:
 *
 * | side | type | vocabulary |
 * |---|---|---|
 * | #308 produces | {@link KeyStorageAssuranceEvidence} | `'none' \| 'issuer-attested' \| 'key-attested'`, plus an OID4VCI Appendix D §D.2 attack-potential grade |
 * | #237 consumes | {@link AssuredKeyStorage} | `'software' \| 'hardware'`, eIDAS-shaped |
 *
 * `credential-assurance.ts` states the hazard the seam has to avoid:
 * *"Collapsing them would let an attestation's mere presence decide a Level of
 * Assurance."* So the presence of a source is never enough here — a GRADE has to
 * clear a floor before anything reads as `'hardware'`.
 *
 * ## The rule, stated once
 *
 * 1. Nothing established (`assurance: 'none'`, or an assurance value this build
 *    does not recognise) → no key storage at all. An entry demanding any key
 *    storage refuses.
 * 2. A source established something AND its graded key storage clears the floor
 *    → `'hardware'`.
 * 3. A source established something at a grade this build RECOGNISES but which
 *    is below the floor → `'software'`. Something is known about the key store
 *    and it is not good enough for an eIDAS `high` reading — that is a
 *    downgrade, not an absence.
 * 4. A source established something but stated NO grade, or stated one this
 *    build does not recognise → no key storage at all. An ungraded claim is an
 *    unevaluated one, and an unevaluated one is not evidence
 *    (`attack-potential.ts`: *"Unknown values rank NOWHERE, deliberately"*).
 *
 * Every comparison is delegated — {@link meetsAttackPotential} for the floor and
 * {@link isAttackPotentialResistance} for the membership test. Neither the
 * ordering nor the fail-closed reading of an unknown grade is re-implemented
 * here, so a level added to the Appendix D union cannot be understood by one
 * module and missed by this one.
 *
 * ## The default floor is the STRICT one
 *
 * An entry that says `requiresKeyStorage: 'hardware'` and nothing else means
 * eIDAS `high`'s secure cryptographic device, so the unstated floor is
 * {@link DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL} — `iso_18045_high`. An operator
 * who wants a lower bar states it; an operator who states nothing gets the
 * reading that cannot over-assert. The permissive default would silently let an
 * `iso_18045_basic` claim satisfy an eIDAS `high` entry, which is precisely the
 * collapse this seam exists to prevent.
 *
 * ## `'issuer-attested'` qualifies, and the source is REPORTED
 *
 * Per #308's own finding, the transitive path is the only key-storage assurance
 * HAIP actually gives a Verifier today, and it is already an explicit operator
 * opt-in (`createStaticAttestingIssuers`). Excluding it would make the whole
 * mechanism unreachable in every deployment that exists. But inherited assurance
 * and verified assurance are not the same proposition, so
 * {@link TranslatedKeyStorage.source} carries which one produced the answer —
 * see that field for why it is on the RESULT rather than on `AssuranceEvidence`.
 */

/**
 * The attack-potential floor an entry gets when it states none.
 *
 * The strongest grade §D.2 states, because eIDAS LoA `high` — a secure
 * cryptographic device — is what an unqualified `requiresKeyStorage: 'hardware'`
 * is asking for, and because a default may only ever be the reading that refuses
 * more, never the one that grants more.
 *
 * Taken from {@link HIGHEST_ATTACK_POTENTIAL_RESISTANCE} rather than written as
 * a literal: #308's placement rule keeps the §D.2 vocabulary inside
 * `attestation/`, and this module is policy, not vocabulary.
 */
export const DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL: AttackPotentialResistance =
  HIGHEST_ATTACK_POTENTIAL_RESISTANCE;

/** What {@link translateKeyStorageAssurance} established. */
export interface TranslatedKeyStorage {
  /**
   * The eIDAS-shaped value to put on `AssuranceEvidence.keyStorage`, or
   * `undefined` when nothing usable was established.
   *
   * Required-but-nullable rather than optional so a reader cannot destructure it
   * without noticing that "nothing established" is one of the answers.
   */
  readonly keyStorage: AssuredKeyStorage | undefined;
  /**
   * WHICH #308 source produced {@link keyStorage} — the D1a corollary.
   *
   * `'key-attested'` means QAuth verified an Appendix D attestation bound to
   * this credential's own key. `'issuer-attested'` means QAuth verified nothing
   * of the sort and is relying on an issuance chain the operator recorded as
   * doing that work. Both can read as `'hardware'`; they are not the same claim,
   * and an operator investigating an assured session must be able to tell them
   * apart.
   *
   * It lives HERE, on the translation's result, rather than on
   * `AssuranceEvidence`: an `AssurancePolicy` must not be able to branch on the
   * source. D1 settled the operator's knob as an attack-potential
   * FLOOR, and putting the source in front of every policy implementation would
   * quietly add a second, undocumented axis — the "both axes" option the owner
   * did not choose. So it is reported to the operator's log, and to nothing that
   * makes a decision.
   *
   * `'none'` whenever nothing was established, including for evidence carrying
   * an assurance value this build does not recognise.
   */
  readonly source: KeyStorageAssurance;
  /**
   * The §D.2 grade a recognised source established, SOURCE-FREE — or
   * `undefined` when no source established anything, or it stated no grade, or
   * it stated one this build does not recognise.
   *
   * This is what lets a POLICY ENTRY state its own floor. The app translates
   * once, before any entry has been selected, so {@link keyStorage} is
   * necessarily read at the default floor; an entry carrying
   * `requiresKeyStorageAttackPotential` re-reads THIS value through
   * {@link keyStorageAtFloor} once the entry is known.
   *
   * It carries the grade and nothing else, deliberately. Passing the raw
   * {@link KeyStorageAssuranceEvidence} to a policy would reintroduce the source
   * as a second operator axis, which D1a forbids (ADR-010 §5). And the grade is
   * only ever populated AFTER the source gate below has run, so a re-read at a
   * lower floor cannot resurrect evidence whose source was `'none'` or
   * unrecognised.
   */
  readonly establishedAttackPotential: AttackPotentialResistance | undefined;
}

/** The result meaning "no source established anything this build can read". */
const NOTHING_ESTABLISHED: TranslatedKeyStorage = Object.freeze({
  keyStorage: undefined,
  source: 'none',
  establishedAttackPotential: undefined,
});

/**
 * The grade → eIDAS key-storage rule, stated ONCE (D1, ADR-010 §5).
 *
 * The half of {@link translateKeyStorageAssurance} that runs AFTER the source
 * gate, factored out because a policy entry stating its own floor has to apply
 * the identical rule to an already-source-checked grade. Two copies of this
 * branch would be the rule stated twice, which is the thing #379 exists to stop.
 *
 * Fail-CLOSED on every uncertainty, and the comparison is delegated entirely to
 * {@link meetsAttackPotential} — which returns `false` for an absent grade, an
 * unrecognised grade AND an unrecognised floor, so none of those can reach
 * `'hardware'`.
 *
 * An unrecognised FLOOR yields `'software'` rather than `undefined`: what is
 * unreadable there is the REQUIREMENT, not the evidence. The grade itself was
 * established and read, so reporting "nothing is known about this key store"
 * would be the inaccurate answer; `'hardware'` stays unreachable either way.
 *
 * @param establishedGrade - the grade a recognised source established, if any.
 * @param minimumAttackPotential - the floor; `undefined` means
 * {@link DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL}.
 * @returns the eIDAS-shaped reading, or `undefined` when there is no grade to
 * read.
 */
export function keyStorageAtFloor(
  establishedGrade: AttackPotentialResistance | undefined,
  minimumAttackPotential?: AttackPotentialResistance
): AssuredKeyStorage | undefined {
  // An ungraded claim is an unevaluated one, and an unevaluated one is not
  // evidence — `'software'` here would be an assertion about where the key lives
  // that nothing supports.
  if (!isAttackPotentialResistance(establishedGrade)) return undefined;

  const floor = minimumAttackPotential ?? DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL;

  return meetsAttackPotential(establishedGrade, floor) ? 'hardware' : 'software';
}

/**
 * Translate #308 key-storage evidence into #237's policy vocabulary (D1).
 *
 * Fail-CLOSED on every uncertainty: `assurance: 'none'`, an unrecognised
 * assurance value, an absent grade, an unrecognised grade and an unrecognised
 * FLOOR all refuse to produce `'hardware'`. The last one is inherited from
 * {@link meetsAttackPotential} rather than re-checked here.
 *
 * Pure and synchronous — it is called on the request path, once per credential.
 *
 * @param evidence - what #308's gate established, straight off
 * `ValidatedCredential.assurance.keyStorageAssurance`. Tolerates `undefined` for
 * a caller that has no evidence at all, which reads as "nothing established".
 * @param minimumAttackPotential - the floor the consuming policy entry states.
 * `undefined` (the ordinary case) means {@link DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL}.
 * @returns the policy value and the source that produced it.
 */
export function translateKeyStorageAssurance(
  evidence: KeyStorageAssuranceEvidence | null | undefined,
  minimumAttackPotential?: AttackPotentialResistance
): TranslatedKeyStorage {
  // Defensive rather than decorative: the evidence arrives on a
  // `ValidatedCredential` that crossed a library boundary, and a policy input
  // that cannot be read must land on "nothing established" rather than throw.
  if (evidence === null || evidence === undefined || typeof evidence !== 'object') {
    return NOTHING_ESTABLISHED;
  }

  const source = evidence.assurance;

  // An assurance value outside the union is an unevaluated one. It must not fall
  // through to the grade check, or a forged evidence object could carry a
  // recognised grade under an unrecognised source and read as `'hardware'`.
  if (source !== 'issuer-attested' && source !== 'key-attested') return NOTHING_ESTABLISHED;

  // Narrowed HERE, once, so that everything downstream of the source gate reads
  // a grade this build understands or nothing at all. An unrecognised grade is
  // dropped rather than forwarded: forwarding it would let a policy entry with a
  // lower floor try to make sense of a value this build cannot rank.
  const establishedAttackPotential = isAttackPotentialResistance(evidence.keyStorage)
    ? evidence.keyStorage
    : undefined;

  return Object.freeze({
    keyStorage: keyStorageAtFloor(establishedAttackPotential, minimumAttackPotential),
    source,
    establishedAttackPotential,
  });
}
