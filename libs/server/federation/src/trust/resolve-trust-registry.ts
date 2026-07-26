import { canonicalizeIssuerIdentifier } from './issuer-identity';
import {
  createStaticIssuerAllowlist,
  DENY_ALL_TRUST_REGISTRY,
  type TrustRegistry,
} from './trust-registry';

/**
 * Resolve which issuers a realm trusts (ADR-004, issue #236).
 *
 * The counterpart of `profiles/resolve-verifier-profile.ts` for the ISSUER
 * trust direction, and deliberately the same shape: a realm view, an env view,
 * one function that is the only supported way to obtain a live registry.
 * Reading `OID4VP_TRUSTED_ISSUERS` directly at a call site is the drift this
 * function exists to prevent.
 *
 * It differs from the profile resolver in one important way: it NEVER returns
 * `undefined`. A profile has two distinguishable refusals because the operator
 * fix differs. Trust does not — "no allowlist" and "empty allowlist" are the
 * same security posture, and returning a registry that trusts nobody means a
 * caller cannot forget to handle the unconfigured case.
 */

/**
 * Minimal structural view of a realm for {@link resolveTrustRegistry}.
 *
 * Mirrors `VerifierProfileRealmLike` (#299): a bare structural type rather than
 * a DB row, so this stays pure and importable without the infra layer.
 *
 * **No `realms.trusted_issuers` column exists yet**, exactly as #299 shipped
 * `verifierProfile` against a column that does not exist. #236 ships per-realm
 * trust *via config*; accepting the realm here means the column (or the
 * dedicated table #236 leaves open) can be added later without touching
 * protocol code or any call site. Values arriving from a DB are untrusted
 * strings and are validated here rather than assumed.
 */
export interface TrustRegistryRealmLike {
  /**
   * `realms.name` — the key `OID4VP_TRUSTED_ISSUERS` is authored against.
   * Absent or blank means no env allowlist can be found for this realm, which
   * resolves to trusting nobody.
   */
  name?: string | null;
  /**
   * Issuers configured ON THE REALM itself, once such a column exists. Present
   * means the realm has expressed a trust policy and the env map is NOT
   * consulted — see {@link resolveTrustRegistry} for why.
   */
  trustedIssuers?: readonly string[] | null;
}

/**
 * Minimal structural view of parsed env config for {@link resolveTrustRegistry}.
 *
 * Structurally satisfied by `@qauth-labs/server-config`'s `TrustRegistryEnv`,
 * without this lib importing it — `server-config` is the lowest layer and must
 * not become a dependency of the layer above it just to name a type.
 */
export interface TrustRegistryEnvLike {
  /** `OID4VP_TRUSTED_ISSUERS`: realm name → trusted issuer identifiers. */
  OID4VP_TRUSTED_ISSUERS?: Readonly<Record<string, readonly string[]>> | null;
}

/**
 * Turn an untrusted candidate list into a registry, or into a deny-all.
 *
 * ALL-OR-NOTHING, and never widening. A list with one malformed entry yields a
 * registry that trusts NOBODY, not a registry built from the entries that
 * happened to parse:
 *
 *  - Honouring the valid subset would apply a trust policy the operator never
 *    wrote, with no signal that it had been altered.
 *  - Falling back to another source (the env map, a default) would replace a
 *    deliberate policy with a different one, which is how a narrow allowlist
 *    silently becomes a wide one.
 *
 * Deny-all is the only direction that cannot grant trust that was not
 * configured.
 */
function toRegistry(candidate: unknown): TrustRegistry {
  if (!Array.isArray(candidate)) return DENY_ALL_TRUST_REGISTRY;

  const canonical: string[] = [];
  for (const entry of candidate as readonly unknown[]) {
    const identifier = canonicalizeIssuerIdentifier(entry);
    if (identifier === undefined) return DENY_ALL_TRUST_REGISTRY;
    canonical.push(identifier);
  }

  // Pre-validated above, so `createStaticIssuerAllowlist` cannot throw here —
  // a corrupt DB row must fail closed, never turn a request into a 500.
  return createStaticIssuerAllowlist(canonical);
}

/**
 * Read one realm's allowlist out of the env map, safely.
 *
 * `Object.hasOwn` rather than a bare property read: `OID4VP_TRUSTED_ISSUERS` is
 * JSON an operator wrote, and a plain lookup for a realm named `constructor` or
 * `toString` on a prototype-bearing object returns something from
 * `Object.prototype` instead of an allowlist. `server-config` already hands
 * back a prototype-less map; this does not rely on that, because the type is
 * structural and any caller can supply a plain object.
 */
function lookupEnvAllowlist(env: TrustRegistryEnvLike | null | undefined, realmName: string) {
  const map = env?.OID4VP_TRUSTED_ISSUERS;
  if (map === null || map === undefined || typeof map !== 'object') return undefined;
  if (!Object.hasOwn(map, realmName)) return undefined;
  return (map as Record<string, unknown>)[realmName];
}

/**
 * Resolve the {@link TrustRegistry} in force for a realm (#236).
 *
 * ## Selection
 *
 * The realm decides; the env map is where a realm's policy is currently
 * written. Precedence is ALL-OR-NOTHING, matching `resolveVerifierProfile`:
 *
 *  - realm `trustedIssuers` **absent** (`null`/`undefined`) → the env map is
 *    consulted for `realm.name`.
 *  - realm `trustedIssuers` **present** → it is authoritative and the env map
 *    is NOT consulted, even when it is empty or malformed. A realm row that
 *    states a policy must not have a deployment-wide value substituted for it;
 *    that substitution is how a realm meant to trust one issuer silently ends
 *    up trusting the deployment's whole set.
 *  - realm missing, unnamed, or absent from the map → deny-all.
 *
 * Note what is NOT here: no deployment-wide fallback list. #236 requires the
 * allowlist to be per realm, so there is no value a realm can inherit merely by
 * existing.
 *
 * ## Fail-closed
 *
 * Every path that cannot positively identify a configured allowlist returns
 * {@link DENY_ALL_TRUST_REGISTRY}. No profile selected, no config, an unknown
 * realm, a corrupt column, a JSON object with a non-array value — all of them
 * trust nobody, and none of them throws.
 *
 * @param realm - a `{ name, trustedIssuers }` view of the realm (may be null).
 * @param env - parsed env carrying the per-realm allowlist map (may be null).
 * @returns the realm's registry; never `undefined`, never permissive by default.
 */
export function resolveTrustRegistry(
  realm: TrustRegistryRealmLike | null | undefined,
  env: TrustRegistryEnvLike | null | undefined
): TrustRegistry {
  const realmSelection = realm?.trustedIssuers;
  if (realmSelection !== null && realmSelection !== undefined) {
    return toRegistry(realmSelection);
  }

  const realmName = realm?.name;
  if (typeof realmName !== 'string' || realmName.trim() === '') {
    return DENY_ALL_TRUST_REGISTRY;
  }

  const configured = lookupEnvAllowlist(env, realmName);
  if (configured === undefined) return DENY_ALL_TRUST_REGISTRY;

  return toRegistry(configured);
}
