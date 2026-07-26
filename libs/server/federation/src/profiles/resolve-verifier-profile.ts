import {
  assertVerifierIdentityProvisioned,
  NO_VERIFIER_MATERIAL,
  type ProvisionedVerifierMaterial,
} from './verifier-identity';
import type { VerifierProfile, VerifierProfileId } from './verifier-profile.types';
import { parseVerifierProfileId, VERIFIER_PROFILES } from './verifier-profiles';

/**
 * Minimal structural view of a realm for {@link resolveVerifierProfile}.
 *
 * Mirrors `EnvironmentRealmLike` (ADR-008): a bare `{ verifierProfile }` rather
 * than a full DB row, so the resolver stays pure and importable without the
 * infra layer.
 *
 * **No `realms.verifier_profile` column exists yet.** The field is read now and
 * is always absent, which is deliberate: #299 ships per-realm selection *via
 * config*, and accepting the realm here means the column can be added later
 * without touching protocol code or any call site. The value may arrive as a raw
 * string from the DB, so it is parsed fail-closed rather than trusted.
 */
export interface VerifierProfileRealmLike {
  verifierProfile?: VerifierProfileId | string | null;
}

/**
 * Minimal structural view of parsed env config for {@link resolveVerifierProfile}.
 */
export interface VerifierProfileEnvLike {
  /** `OID4VP_VERIFIER_PROFILE`; absent means no deployment-wide selection. */
  OID4VP_VERIFIER_PROFILE?: VerifierProfileId | string | null;
}

/**
 * Resolve the active {@link VerifierProfile} for a realm (issue #299).
 *
 * The single entry point for "which profile is in force", and the only way to
 * RESOLVE one — the provisioning assertion is folded in rather than left as a
 * separate step a caller might forget. That is structural, not stylistic:
 * `assertVerifierIdentityProvisioned` used to run once at bootstrap against the
 * env-level profile, so once `realms.verifier_profile` lands a realm row could
 * hand back a profile whose X.509 material had never been asserted. A profile
 * this function returns is always one whose verifier identity the deployment
 * can actually prove.
 *
 * `VERIFIER_PROFILES` remains exported as the data table it is, and reading an
 * entry out of it is a lookup, not a resolution: it carries no claim that this
 * deployment can operate that profile. Anything deciding posture for a live
 * request must come through here.
 *
 * ## Selection
 *
 * The realm decides, and the env is the deployment-wide default it falls back
 * to. Realm selection is ALL-OR-NOTHING, which is where this deliberately
 * diverges from `resolveEnvironmentPolicy` (ADR-008 §7): that resolver composes
 * two values by taking the STRICTER of them, because `production` is a safe
 * default for anything unparseable. No such default exists here — `haip-1.0` is
 * not a stricter `oid4vp-1.0-base`, it is a different ecosystem — so instead of
 * composing, a realm that selected something must have selected something valid:
 *
 *   - realm value ABSENT (`null`/`undefined`) → the env default is consulted.
 *   - realm value PRESENT but unrecognised → `undefined`. The env is NOT
 *     consulted. A realm row meant to run `haip-1.0` with a typo'd value would
 *     otherwise silently run the deployment default: unencrypted `direct_post`,
 *     revoked credentials accepted — the "permissive fallback to the more
 *     capable profile" #296 LOCKED against, in reverse.
 *   - realm value PRESENT and recognised → that profile, env ignored.
 *
 * ## Two distinguishable refusals
 *
 * Both are refusals, and the caller must be able to tell them apart because the
 * operator fix differs:
 *
 *   - **`undefined`** — nothing usable was selected. The caller decides what
 *     that means: the bootstrap turns it into a startup failure, a future
 *     request path turns it into a rejected flow, from the same signal.
 *   - **throws** — a profile WAS selected, but its preferred Client Identifier
 *     Prefix lacks the X.509 material it requires. Half-configured, not
 *     unconfigured. This matches how the bootstrap already behaves and is why
 *     the two cases are not collapsed into a single `undefined`.
 *
 * @param realm - a `{ verifierProfile }` view of the realm (may be null/undefined).
 * @param env - parsed env carrying the deployment-wide default.
 * @param provisioned - X.509 material the operator supplied; defaults to none,
 * so a caller that does not thread it through gets today's fail-closed answer.
 * @returns the active profile, or `undefined` when wallet flows must be refused.
 * @throws Error when the selected profile is not provisioned (see above).
 */
export function resolveVerifierProfile(
  realm: VerifierProfileRealmLike | null | undefined,
  env: VerifierProfileEnvLike | null | undefined,
  provisioned: ProvisionedVerifierMaterial = NO_VERIFIER_MATERIAL
): VerifierProfile | undefined {
  const realmSelection = realm?.verifierProfile;

  // Absent means "this realm expressed no opinion"; anything else — including a
  // corrupt or empty string — is an expressed opinion that must parse. No
  // trimming, no coercion: normalising a bad value here is how a downgrade
  // becomes silent.
  const selected =
    realmSelection === null || realmSelection === undefined
      ? env?.OID4VP_VERIFIER_PROFILE
      : realmSelection;

  const id = parseVerifierProfileId(selected);
  if (id === undefined) return undefined;

  const profile = VERIFIER_PROFILES[id];
  assertVerifierIdentityProvisioned(profile, provisioned);

  return profile;
}
