/**
 * Attack Potential Resistance — OID4VCI Appendix D §D.2 (issue #308).
 *
 * ## What the vocabulary actually measures
 *
 * A key attestation does not say "this key is in secure hardware"; it says how
 * much ATTACK POTENTIAL the component holding the key resists, keyed to the
 * ISO/IEC 18045 attack-potential calculation used by Common Criteria. Two
 * components are described independently:
 *
 *  - `key_storage` — the resistance of the component that stores the private
 *    key. This is the WSCD question #308 exists to answer.
 *  - `user_authentication` — the resistance of whatever gates USE of that key
 *    (the wallet's PIN or biometric). A key in certified hardware that anyone
 *    holding the phone can exercise is a different assurance proposition from
 *    the same key behind a certified authenticator, which is why the spec keeps
 *    the two apart and so does this module.
 *
 * ## Why the levels are ORDERED here and nowhere else
 *
 * "At least moderate" is the only useful way to state a policy, and comparing
 * enum members is only meaningful against a declared order. Putting that order
 * in one exported table means a profile can express a floor
 * (`minimumKeyStorageAttackPotential`) as data instead of as a chain of
 * comparisons scattered through the validator.
 *
 * ## Unknown values rank NOWHERE, deliberately
 *
 * {@link rankAttackPotentialResistance} returns `undefined` for anything not in
 * the table, and every comparison treats that as "does not meet the floor".
 * A wallet ecosystem that mints its own level string must not be able to clear
 * a `moderate` floor by claiming `super_extra_high`: an unrecognised level is
 * an unevaluated one, and an unevaluated one is not evidence.
 *
 * ## Placement (#308 acceptance criterion)
 *
 * These constants are HAIP/OID4VCI-specific, and the #299 rule is that no
 * HAIP-specific constant may appear outside the `haip-1.0` profile entry and
 * this adapter. This module IS that adapter's vocabulary: the strings live here
 * and are referenced by the `haip-1.0` table entry, and nowhere else.
 *
 * @see https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html
 *   Appendix D (Key Attestation), §D.2 (Attack Potential Resistance)
 */

/**
 * The attack-potential resistance levels OID4VCI Appendix D §D.2 enumerates.
 *
 * Written exactly as the specification spells them — including the hyphen in
 * `enhanced-basic`, which is the one member whose shape differs from the rest
 * and therefore the one most likely to be "tidied" into `enhanced_basic` by a
 * future edit. A near-miss would silently become an unrecognised level, which
 * fails closed but would look like a wallet-compatibility bug.
 */
export type AttackPotentialResistance =
  'iso_18045_basic' | 'iso_18045_enhanced-basic' | 'iso_18045_moderate' | 'iso_18045_high';

/**
 * The levels in ASCENDING order of resistance.
 *
 * The single source of the ordering. `rankAttackPotentialResistance` is derived
 * from it rather than restating it, so a level cannot be added to the union and
 * forgotten by the comparison.
 */
export const ATTACK_POTENTIAL_RESISTANCE_ORDER: readonly AttackPotentialResistance[] =
  Object.freeze([
    'iso_18045_basic',
    'iso_18045_enhanced-basic',
    'iso_18045_moderate',
    'iso_18045_high',
  ]);

/**
 * The strongest level the table states.
 *
 * Exported so that a POLICY outside this adapter can state a floor of "the
 * strongest resistance §D.2 grades" without naming the string — #308's placement
 * rule is that no HAIP-specific key-attestation constant appears outside the
 * `haip-1.0` profile entry and this adapter, and the #237 translation
 * (`assurance/key-storage-evidence.ts`) needs exactly one such floor as its
 * default. Pinned to the last member of
 * {@link ATTACK_POTENTIAL_RESISTANCE_ORDER} by test rather than computed from
 * it: a level added to the table must be a deliberate edit here too, because
 * silently re-pointing every policy default at a brand-new grade would stop
 * every already-granting deployment from granting.
 */
export const HIGHEST_ATTACK_POTENTIAL_RESISTANCE: AttackPotentialResistance = 'iso_18045_high';

/**
 * Narrow an untrusted value to an {@link AttackPotentialResistance}.
 *
 * The input comes out of an attacker-influenced JWT payload, so this is a
 * membership test rather than a cast: everything unrecognised — including
 * `null`, a number, or a level from some other ecosystem's vocabulary — is
 * rejected outright.
 *
 * @param value - anything.
 * @returns whether `value` is a level this verifier understands.
 */
export function isAttackPotentialResistance(value: unknown): value is AttackPotentialResistance {
  return (
    typeof value === 'string' &&
    (ATTACK_POTENTIAL_RESISTANCE_ORDER as readonly string[]).includes(value)
  );
}

/**
 * Rank a level, strongest highest.
 *
 * @param value - a level, or anything at all.
 * @returns its 1-based rank, or `undefined` when the value is not a level this
 * verifier understands. `undefined` rather than `0`: a caller doing arithmetic
 * on an unknown level should get a type error, not a comparison that quietly
 * treats "we have no idea" as "the weakest level we know".
 */
export function rankAttackPotentialResistance(value: unknown): number | undefined {
  if (!isAttackPotentialResistance(value)) return undefined;
  return ATTACK_POTENTIAL_RESISTANCE_ORDER.indexOf(value) + 1;
}

/**
 * Whether `actual` resists at least as much attack potential as `minimum`.
 *
 * Fail-CLOSED on every uncertainty: an absent level, an unrecognised level, and
 * an unrecognised FLOOR all return `false`. The last one matters most — a
 * profile that declared a floor this build does not understand must refuse
 * everything, not accept everything, because the alternative is that a typo in
 * a profile table silently disables the check it was added to impose.
 *
 * @param actual - the level attested, if any.
 * @param minimum - the floor the active profile requires.
 * @returns whether the floor is met.
 */
export function meetsAttackPotential(actual: unknown, minimum: unknown): boolean {
  const actualRank = rankAttackPotentialResistance(actual);
  const minimumRank = rankAttackPotentialResistance(minimum);

  if (actualRank === undefined || minimumRank === undefined) return false;

  return actualRank >= minimumRank;
}

/**
 * Reduce a key attestation's `key_storage` / `user_authentication` array to the
 * single level it establishes.
 *
 * Appendix D models each as a LIST, and a list of resistance claims has exactly
 * one honest reading: the component resists the WEAKEST level it lists. A key
 * storage that claims both `iso_18045_high` and `iso_18045_basic` is telling us
 * there is a path to it that only resists basic attack potential, and taking
 * the maximum would let any wallet clear any floor by appending `high` to its
 * list.
 *
 * An entry the verifier does not recognise poisons the whole list for the same
 * reason: it may describe a weaker path, and this verifier cannot tell.
 *
 * @param values - the raw claim value, unverified and of unknown shape.
 * @returns the established level, or `undefined` when the claim is absent,
 * empty, not an array, or carries anything unrecognised.
 */
export function reduceAttackPotentialClaim(values: unknown): AttackPotentialResistance | undefined {
  if (!Array.isArray(values) || values.length === 0) return undefined;

  let weakest: AttackPotentialResistance | undefined;
  let weakestRank = Number.POSITIVE_INFINITY;

  for (const value of values) {
    const rank = rankAttackPotentialResistance(value);
    if (rank === undefined) return undefined;
    if (rank < weakestRank) {
      weakestRank = rank;
      weakest = value as AttackPotentialResistance;
    }
  }

  return weakest;
}
