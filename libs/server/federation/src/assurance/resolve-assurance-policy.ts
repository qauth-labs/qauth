import { canonicalizeIssuerIdentifier } from '../trust/issuer-identity';
import type { AcrBearingAssuranceLevel } from './acr-value';
import {
  type AssurancePolicy,
  createIssuerAssurancePolicy,
  type IssuerAssuranceEntry,
  LOW_ONLY_ASSURANCE_POLICY,
} from './credential-assurance';

/**
 * Resolve which issuers a realm considers assured, and at what level (ADR-004,
 * ADR-010, issue #237).
 *
 * The counterpart of `trust/resolve-trust-registry.ts` for the ASSURANCE
 * question, and deliberately the same shape: a realm view, an env view, one
 * function that is the only supported way to obtain a live policy. Reading
 * `OID4VP_ISSUER_ASSURANCE` at a call site is the drift this function exists to
 * prevent.
 *
 * Like the trust resolver it NEVER returns `undefined`: "no policy" and "assures
 * nothing" are the same posture, so an unconfigured deployment gets
 * {@link LOW_ONLY_ASSURANCE_POLICY} and a caller cannot forget to handle the
 * unconfigured case.
 *
 * ## Separate configuration from the trust allowlist, on purpose
 *
 * `OID4VP_TRUSTED_ISSUERS` (#236) and `OID4VP_ISSUER_ASSURANCE` (#237) answer
 * different questions — *may we accept this issuer* versus *what is it worth* —
 * and merging them would make one of the two answers implicit. An issuer must
 * appear in BOTH to produce an assured session: trust is asserted by the gate
 * that throws, and assurance by this policy. Listing an issuer here does not
 * make it trusted, which is why every consumer runs `assertIssuerTrusted` first.
 */

/**
 * One configured statement about an issuer, as it appears in configuration.
 *
 * Structurally satisfied by `@qauth-labs/server-config`'s parsed value without
 * this lib importing it — `server-config` is the lowest layer and must not
 * become a dependency of the layer above it just to name a type.
 */
export interface ConfiguredIssuerAssurance {
  /** The eIDAS LoA credentials from this issuer are worth. Never `'low'`. */
  level?: string | null;
  /**
   * `vct` values this statement covers. Absent covers every credential type the
   * issuer signs — see {@link IssuerAssuranceEntry.credentialTypes}.
   */
  credentialTypes?: readonly string[] | null;
}

/** Issuer identifier → what credentials from it are worth. */
export type ConfiguredIssuerAssuranceMap = Readonly<Record<string, ConfiguredIssuerAssurance>>;

/**
 * Minimal structural view of a realm for {@link resolveAssurancePolicy}.
 *
 * **No `realms.issuer_assurance` column exists yet**, exactly as #236 shipped
 * `trustedIssuers` and #299 shipped `verifierProfile` against columns that do
 * not exist. Accepting the realm here means the column (or a dedicated table)
 * can be added later without touching protocol code or any call site. Values
 * arriving from a DB are untrusted and are validated here rather than assumed.
 */
export interface AssurancePolicyRealmLike {
  /**
   * `realms.name` — the key `OID4VP_ISSUER_ASSURANCE` is authored against.
   * Absent or blank means no env policy can be found for this realm, which
   * resolves to assuring nothing.
   */
  name?: string | null;
  /**
   * Assurance configured ON THE REALM itself, once such a column exists.
   * Present means the realm has expressed a policy and the env map is NOT
   * consulted — see {@link resolveAssurancePolicy}.
   */
  issuerAssurance?: ConfiguredIssuerAssuranceMap | null;
}

/**
 * Minimal structural view of parsed env config for
 * {@link resolveAssurancePolicy}. Structurally satisfied by
 * `@qauth-labs/server-config`'s `AssuranceEnv`.
 */
export interface AssurancePolicyEnvLike {
  /** `OID4VP_ISSUER_ASSURANCE`: realm name → issuer → assurance statement. */
  OID4VP_ISSUER_ASSURANCE?: Readonly<Record<string, ConfiguredIssuerAssuranceMap>> | null;
}

/** Levels an operator may configure. `'low'` is not one of them — it is the default. */
function parseConfiguredLevel(value: unknown): AcrBearingAssuranceLevel | undefined {
  if (value !== 'substantial' && value !== 'high') return undefined;
  return value;
}

/**
 * Turn an untrusted candidate map into a policy, or into an assures-nothing.
 *
 * ALL-OR-NOTHING, and never widening — the same rule
 * `resolveTrustRegistry#toRegistry` applies. A map with one malformed entry
 * yields {@link LOW_ONLY_ASSURANCE_POLICY}, not a policy built from the entries
 * that happened to parse: honouring the valid subset would apply an assurance
 * policy the operator never wrote, with no signal that it had been altered.
 *
 * Note the asymmetry with {@link createIssuerAssurancePolicy}, which DROPS a
 * malformed entry instead. That function is the low-level builder and its
 * leniency is a defence against a caller that skipped validation; this function
 * is the validated boundary, and at a boundary "some of your policy" is worse
 * than "none of it".
 */
function toPolicy(candidate: unknown): AssurancePolicy {
  if (candidate === null || typeof candidate !== 'object' || Array.isArray(candidate)) {
    return LOW_ONLY_ASSURANCE_POLICY;
  }

  const entries: IssuerAssuranceEntry[] = [];
  for (const [rawIssuer, rawStatement] of Object.entries(candidate as Record<string, unknown>)) {
    const issuer = canonicalizeIssuerIdentifier(rawIssuer);
    if (issuer === undefined) return LOW_ONLY_ASSURANCE_POLICY;
    if (rawStatement === null || typeof rawStatement !== 'object' || Array.isArray(rawStatement)) {
      return LOW_ONLY_ASSURANCE_POLICY;
    }

    const statement = rawStatement as ConfiguredIssuerAssurance;
    const assuranceLevel = parseConfiguredLevel(statement.level);
    if (assuranceLevel === undefined) return LOW_ONLY_ASSURANCE_POLICY;

    const rawTypes = statement.credentialTypes;
    if (rawTypes === null || rawTypes === undefined) {
      entries.push({ issuer, assuranceLevel });
      continue;
    }
    if (!Array.isArray(rawTypes)) return LOW_ONLY_ASSURANCE_POLICY;
    const credentialTypes: string[] = [];
    for (const credentialType of rawTypes as readonly unknown[]) {
      if (typeof credentialType !== 'string' || credentialType.trim() === '') {
        return LOW_ONLY_ASSURANCE_POLICY;
      }
      credentialTypes.push(credentialType);
    }
    // An explicit but EMPTY type list covers nothing, so it would silently be a
    // no-op entry. Refuse the whole map instead: the operator wrote something
    // they believed had an effect.
    if (credentialTypes.length === 0) return LOW_ONLY_ASSURANCE_POLICY;
    entries.push({ issuer, assuranceLevel, credentialTypes });
  }

  return createIssuerAssurancePolicy(entries);
}

/**
 * Read one realm's assurance map out of the env map, safely.
 *
 * `Object.hasOwn` rather than a bare property read, for the same reason
 * `resolveTrustRegistry` uses it: `OID4VP_ISSUER_ASSURANCE` is JSON an operator
 * wrote, and a plain lookup for a realm named `constructor` on a
 * prototype-bearing object returns something from `Object.prototype` instead of
 * a policy.
 */
function lookupEnvAssurance(
  env: AssurancePolicyEnvLike | null | undefined,
  realmName: string
): unknown {
  const map = env?.OID4VP_ISSUER_ASSURANCE;
  if (map === null || map === undefined || typeof map !== 'object') return undefined;
  if (!Object.hasOwn(map, realmName)) return undefined;
  return (map as Record<string, unknown>)[realmName];
}

/**
 * Resolve the {@link AssurancePolicy} in force for a realm (#237).
 *
 * ## Selection
 *
 * Identical precedence to `resolveTrustRegistry`, so the two trust-adjacent
 * resolutions cannot drift:
 *
 *  - realm `issuerAssurance` **absent** → the env map is consulted for
 *    `realm.name`.
 *  - realm `issuerAssurance` **present** → authoritative; the env map is NOT
 *    consulted, even when empty or malformed.
 *  - realm missing, unnamed, or absent from the map → assures nothing.
 *
 * There is no deployment-wide fallback: an issuer assured for one tenant must
 * not become assured for every other tenant merely by existing.
 *
 * @param realm - a `{ name, issuerAssurance }` view of the realm (may be null).
 * @param env - parsed env carrying the per-realm assurance map (may be null).
 * @returns the realm's policy; never `undefined`, never assuring by default.
 */
export function resolveAssurancePolicy(
  realm: AssurancePolicyRealmLike | null | undefined,
  env: AssurancePolicyEnvLike | null | undefined
): AssurancePolicy {
  const realmSelection = realm?.issuerAssurance;
  if (realmSelection !== null && realmSelection !== undefined) {
    return toPolicy(realmSelection);
  }

  const realmName = realm?.name;
  if (typeof realmName !== 'string' || realmName.trim() === '') {
    return LOW_ONLY_ASSURANCE_POLICY;
  }

  const configured = lookupEnvAssurance(env, realmName);
  if (configured === undefined) return LOW_ONLY_ASSURANCE_POLICY;

  return toPolicy(configured);
}
