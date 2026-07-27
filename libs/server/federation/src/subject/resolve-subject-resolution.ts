import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import type { VerifierProfile } from '../profiles/verifier-profile.types';
import type { SubjectResolutionStrategyId } from './subject-resolution.types';
import {
  normalizeBindingClaims,
  normalizeClaimName,
  normalizeIssuerScopedIssuers,
} from './subject-resolution-config';
import {
  assertSubjectResolutionStrategySelectable,
  parseSubjectResolutionStrategyId,
  type SubjectResolutionConfig,
} from './subject-resolution-strategies';

/**
 * Resolving which subject-resolution strategy is in force (issue #300).
 *
 * Deliberately the same shape as `resolveVerifierProfile` (#299) — realm first,
 * env as the deployment-wide default, all-or-nothing realm selection, and two
 * distinguishable refusals — because the two answer the same KIND of question
 * ("what posture is this realm running?") and an operator should not have to
 * learn two resolution models.
 *
 * The third input is new: a {@link VerifierProfile} supplies the fail-closed
 * DEFAULT. ADR-009's Consequences record exactly this composition — *"The
 * `VerifierProfile` abstraction (#299) gains a per-profile default strategy; the
 * two abstractions compose without either changing shape."*
 */

/**
 * Minimal structural view of a realm.
 *
 * Mirrors `VerifierProfileRealmLike`: a bare field rather than a full DB row, so
 * the resolver stays pure and importable without the infra layer.
 *
 * **No `realms.subject_resolution` column exists yet.** The field is read now
 * and is always absent, which is deliberate for the same reason #299 reads a
 * `verifierProfile` that no column supplies: per-realm selection can be added
 * later without touching protocol code or any call site. The value may arrive as
 * a raw string from the DB, so it is parsed fail-closed rather than trusted.
 */
export interface SubjectResolutionRealmLike {
  subjectResolution?: SubjectResolutionStrategyId | string | null;
}

/**
 * Minimal structural view of parsed env config.
 *
 * The four variables are read as a group: the strategy id selects WHICH
 * strategy, and the rest supply what that strategy needs. A deployment that
 * names a strategy and omits its settings is HALF-configured, and this resolver
 * throws rather than quietly building a weaker strategy.
 */
export interface SubjectResolutionEnvLike {
  /** `OID4VP_SUBJECT_RESOLUTION`; absent means "use the profile default". */
  OID4VP_SUBJECT_RESOLUTION?: SubjectResolutionStrategyId | string | null;
  /** `OID4VP_SUBJECT_BINDING_CLAIMS`; the `asserted-lookup` entitlement check. */
  OID4VP_SUBJECT_BINDING_CLAIMS?: readonly string[] | null;
  /** `OID4VP_SUBJECT_CLAIM`; the `issuer-scoped-claim` subject claim. */
  OID4VP_SUBJECT_CLAIM?: string | null;
  /** `OID4VP_SUBJECT_CLAIM_ISSUERS`; the issuers `issuer-scoped-claim` is opted into. */
  OID4VP_SUBJECT_CLAIM_ISSUERS?: readonly string[] | null;
}

/** The profile fields this resolver reads — nothing else. */
export type SubjectResolutionProfileLike = Pick<VerifierProfile, 'defaultSubjectResolution'>;

/**
 * Select the strategy id, without building anything.
 *
 * Selection order, all-or-nothing at the realm exactly as #299 does it:
 *
 *   - realm value ABSENT (`null`/`undefined`) → the env is consulted;
 *   - realm value PRESENT but unrecognised → `undefined`. The env is NOT
 *     consulted, and neither is the profile default. A realm row meant to run
 *     `issuer-scoped-claim` with a typo'd value would otherwise silently run the
 *     deployment default — a different account-keying model, applied without
 *     anyone choosing it;
 *   - realm value PRESENT and recognised → that id;
 *   - no realm value and no env value → the profile's default.
 *
 * @param realm - a `{ subjectResolution }` view of the realm (may be absent).
 * @param env - parsed env carrying the deployment-wide selection.
 * @param profile - supplies the fail-closed default.
 * @returns the selected id, or `undefined` when nothing usable was selected.
 * @throws InvalidConfigurationError when the selected strategy exists but a
 * deployment may not select it (see
 * {@link assertSubjectResolutionStrategySelectable}).
 */
export function resolveSubjectResolutionStrategyId(
  realm: SubjectResolutionRealmLike | null | undefined,
  env: SubjectResolutionEnvLike | null | undefined,
  profile: SubjectResolutionProfileLike
): SubjectResolutionStrategyId | undefined {
  const realmSelection = realm?.subjectResolution;

  if (realmSelection !== null && realmSelection !== undefined) {
    const id = parseSubjectResolutionStrategyId(realmSelection);
    if (id === undefined) return undefined;
    assertSubjectResolutionStrategySelectable(id);
    return id;
  }

  const envSelection = env?.OID4VP_SUBJECT_RESOLUTION;
  if (envSelection !== null && envSelection !== undefined) {
    const id = parseSubjectResolutionStrategyId(envSelection);
    if (id === undefined) return undefined;
    assertSubjectResolutionStrategySelectable(id);
    return id;
  }

  // The profile's default is itself a selection — the profile made it — so it
  // goes through the same gate. A future profile defaulting to a gated strategy
  // must fail the boot, not be quietly honoured because the table said so.
  const fallback = parseSubjectResolutionStrategyId(profile?.defaultSubjectResolution);
  if (fallback === undefined) return undefined;
  assertSubjectResolutionStrategySelectable(fallback);

  return fallback;
}

/** Read a configured string list, treating an absent one as empty. */
function configuredList(value: readonly string[] | null | undefined): readonly string[] {
  return Array.isArray(value) ? value : [];
}

/**
 * Resolve the fully-specified strategy configuration for a realm (#300).
 *
 * The single entry point for "how does this deployment resolve accounts", and
 * the only way to obtain a configuration — the settings assertions are folded in
 * rather than left as a separate step a caller might forget, exactly as
 * `resolveVerifierProfile` folds in `assertVerifierIdentityProvisioned`.
 *
 * ## Two distinguishable refusals, and why the operator fix differs
 *
 *   - **`undefined`** — nothing usable was selected. The caller decides what
 *     that means: a bootstrap turns it into a startup failure, a request path
 *     into a refused flow, from the same signal.
 *   - **throws** — a strategy WAS selected, and it is either one a deployment
 *     may not select, or one whose required settings are missing.
 *     Half-configured, not unconfigured.
 *
 * Note where the default lands: a deployment that configures nothing at all gets
 * `asserted-lookup` from the profile and then a THROW, because it named no
 * binding claims. That is the intended outcome — `asserted-lookup` without an
 * entitlement check is ADR-009 §1's total authentication bypass, so "the
 * operator configured nothing" must be a refusal rather than a strategy that
 * authenticates everyone.
 *
 * A configuration this function RETURNS is always one
 * `createSubjectResolutionStrategy` can build: every per-strategy setting is
 * validated here.
 *
 * @param realm - a `{ subjectResolution }` view of the realm (may be absent).
 * @param env - parsed env carrying the selection and the per-strategy settings.
 * @param profile - the active `VerifierProfile`, for its default.
 * @returns the configuration, or `undefined` when wallet flows must be refused.
 * @throws InvalidConfigurationError when the selection is half-configured.
 */
export function resolveSubjectResolution(
  realm: SubjectResolutionRealmLike | null | undefined,
  env: SubjectResolutionEnvLike | null | undefined,
  profile: SubjectResolutionProfileLike
): SubjectResolutionConfig | undefined {
  const id = resolveSubjectResolutionStrategyId(realm, env, profile);
  if (id === undefined) return undefined;

  // Validated HERE, not left to `createSubjectResolutionStrategy`, so that a
  // configuration this function returns is always one a strategy can be built
  // from. Same structural reason `resolveVerifierProfile` folds in
  // `assertVerifierIdentityProvisioned`: a separate second step is a step a
  // caller can forget, and forgetting this one means a deployment that looks
  // resolved and then fails at the first presentation instead of at boot.
  const bindingClaims = normalizeBindingClaims(
    configuredList(env?.OID4VP_SUBJECT_BINDING_CLAIMS),
    'OID4VP_SUBJECT_BINDING_CLAIMS'
  );

  if (id === 'asserted-lookup') {
    return { strategy: 'asserted-lookup', bindingClaims };
  }

  if (id === 'issuer-scoped-claim') {
    return {
      strategy: 'issuer-scoped-claim',
      subjectClaim: normalizeClaimName(env?.OID4VP_SUBJECT_CLAIM, 'OID4VP_SUBJECT_CLAIM'),
      issuers: normalizeIssuerScopedIssuers(
        configuredList(env?.OID4VP_SUBJECT_CLAIM_ISSUERS),
        'OID4VP_SUBJECT_CLAIM_ISSUERS'
      ),
      // ADR-009 §2 requires the fallback unconditionally, so it is built from
      // the same binding claims an `asserted-lookup` deployment would use. A
      // deployment that opts into `issuer-scoped-claim` therefore still has to
      // configure the fallback's entitlement check — the holder may withhold the
      // subject claim on any presentation, and the fallback must be as strong
      // then as the primary strategy is now.
      fallback: { bindingClaims },
    };
  }

  // Unreachable while every non-login id is refused by
  // `assertSubjectResolutionStrategySelectable`, which runs above. Restated
  // rather than assumed: this is the branch a future `login` strategy lands in
  // if someone adds it to the table and forgets this resolver.
  throw new InvalidConfigurationError(
    `Subject-resolution strategy '${id}' has no configuration mapping in resolveSubjectResolution (#300).`,
    { strategy: id }
  );
}
