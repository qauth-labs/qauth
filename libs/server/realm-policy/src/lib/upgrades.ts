import { PolicyDefinitionError } from './field';
import { compareSchemaVersions, isPolicySchemaVersion } from './version';

/**
 * The upgrades of stored realm policies (#908): how a document an earlier
 * release stored under an older schema version reads under a later one.
 *
 * The realm row keeps its policies under the schema version they were written
 * in (`policy_schema_version`), and a release that changes the version
 * (`REALM_POLICY_SCHEMA_VERSION`) does not rewrite them. So it ships an
 * upgrade from the version before it, and the policy store applies the
 * upgrades from a document's version to its own when it reads one: the
 * document reads as it would had this release written it, and the next write
 * (the boot's `seedRealms`, or an update) stores it under this release's
 * version. A document of an older version the upgrades do not reach is
 * refused: read with the new schema, a renamed field would read as its seed,
 * which may be looser than what the realm stored.
 */

/** One version change of the realm policy schema, and how a document of the old version reads under the new one. */
export interface PolicySchemaUpgrade {
  /** The version of the documents it reads. */
  readonly from: string;
  /** The version of the documents it gives: the next one, later than `from`. */
  readonly to: string;
  /**
   * The document of version `to` that `document`, of version `from`, stands
   * for. It gets a copy, which it may change and return.
   *
   * Never looser than stored: a renamed field keeps its value, a narrowed one
   * takes the nearest value the new schema accepts that is as strict or
   * stricter, a removed one is removed. A member it does not know (a group a
   * later release registered within `from`) is left as it is, and so is a
   * field it does not change; a field it does not set takes its seed, as in
   * any stored document. A stored document holds no secret field, so an
   * upgrade cannot move one.
   */
  readonly upgrade: (document: Record<string, unknown>) => Record<string, unknown>;
}

/**
 * The upgrades of QAuth's realm policy registry, one per version change,
 * oldest first: none while the version is still the first one,
 * {@link FIRST_REALM_POLICY_SCHEMA_VERSION}. The release that changes
 * `REALM_POLICY_SCHEMA_VERSION` appends its upgrade here, and the contract
 * test holds it to that.
 */
export const REALM_POLICY_UPGRADES: readonly PolicySchemaUpgrade[] = Object.freeze([]);

/**
 * The upgrades that lead from each older version to `target`, in the order
 * they apply: what the policy store reads a stored document with.
 *
 * @throws PolicyDefinitionError when an upgrade names a version that is not
 *   one, goes back or nowhere, goes past `target`, shares its `from` with
 *   another, or leads to a version from which no upgrade reaches `target`
 */
export function upgradePathsTo(
  upgrades: readonly PolicySchemaUpgrade[],
  target: string
): ReadonlyMap<string, readonly PolicySchemaUpgrade[]> {
  const byFrom = new Map<string, PolicySchemaUpgrade>();
  for (const upgrade of upgrades) {
    const { from, to } = upgrade;
    if (!isPolicySchemaVersion(from) || !isPolicySchemaVersion(to)) {
      throw new PolicyDefinitionError(
        `An upgrade of the realm policies goes from and to policy schema versions, not "${String(from)}" and "${String(to)}"`
      );
    }
    if (typeof upgrade.upgrade !== 'function') {
      throw new PolicyDefinitionError(`The upgrade from ${from} has no upgrade function`);
    }
    if (compareSchemaVersions(from, to) >= 0) {
      throw new PolicyDefinitionError(`The upgrade from ${from} to ${to} does not go forward`);
    }
    if (compareSchemaVersions(to, target) > 0) {
      throw new PolicyDefinitionError(
        `The upgrade from ${from} to ${to} goes past the registry's version, ${target}`
      );
    }
    if (byFrom.has(from)) {
      throw new PolicyDefinitionError(`Two upgrades of the realm policies go from ${from}`);
    }
    byFrom.set(from, Object.freeze({ ...upgrade }));
  }

  const paths = new Map<string, readonly PolicySchemaUpgrade[]>();
  for (const from of byFrom.keys()) {
    const steps: PolicySchemaUpgrade[] = [];
    let version = from;
    // Every step goes forward and no further than `target`, so the walk ends.
    while (version !== target) {
      const step = byFrom.get(version);
      if (step === undefined) {
        throw new PolicyDefinitionError(
          `The upgrades of the realm policies lead from ${from} to ${version}, and none from there to ${target}`
        );
      }
      steps.push(step);
      version = step.to;
    }
    paths.set(from, Object.freeze(steps));
  }
  return paths;
}
