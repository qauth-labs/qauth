import { isDeepStrictEqual } from 'node:util';

import { compareDirection, sameEntries } from './direction';
import { directionKind, isSetDirection } from './field';
import { REALM_POLICY_ENV, REALM_POLICY_REGISTRY } from './realm-policies';
import type { PolicyEnvReader, PolicyRegistry } from './registry';

/** A seed key the environment sets, and the policy field it seeds. */
export interface SetSeedKey {
  /** The key's current name; an old name the environment uses counts under it. */
  readonly key: string;
  /** The dotted path of the field it seeds, such as `tokens.accessTokenLifespanSeconds`. */
  readonly path: string;
}

/**
 * The seed keys `env` sets, of the fields a policy document holds (#516):
 * what a realm that already has its policies ignores, since the environment
 * only seeds a new realm (ADR-019 Decision 10). The boot step logs each one.
 *
 * `env` is the raw environment (`process.env`): a value its env schema filled
 * in was not set. A blank value is unset. An old key name counts under its
 * current one, as the server reads it. Secret fields are left out: their seed
 * keys feed the realm's secret store (#529), not the document.
 */
export function seedKeysSetIn(
  env: Readonly<Record<string, string | undefined>>,
  registry: PolicyRegistry = REALM_POLICY_REGISTRY,
  reader: Pick<PolicyEnvReader, 'applyAliases'> = REALM_POLICY_ENV
): SetSeedKey[] {
  const strings: Record<string, string> = {};
  for (const [key, value] of Object.entries(env)) {
    if (typeof value === 'string') strings[key] = value;
  }
  const aliased = reader.applyAliases(strings);
  const set: SetSeedKey[] = [];
  for (const { path, field } of registry.fields()) {
    if (field.secret || field.seedEnv === null) continue;
    const value = aliased[field.seedEnv];
    if (typeof value === 'string' && value.trim() !== '') {
      set.push({ key: field.seedEnv, path });
    }
  }
  return set;
}

/** How a seed key's value compares with a realm's stored value; see {@link compareSeedWithStored}. */
export type SeedComparison = 'same' | 'stricter' | 'looser' | 'different';

/**
 * How the value a seed key gives a field compares with the value a realm
 * stores (#529, from the review of #516): what the boot says about a seed
 * key the environment still sets once the server reads the field from the
 * realm row.
 *
 * - `same`: the two agree (a set field's lists in any order).
 * - `stricter`: the environment's value is stricter, by the field's
 *   direction; the stored, looser value applies.
 * - `looser`: the environment's value is looser; the stored one applies.
 * - `different`: they differ and the field has no order (`opaque`, such as
 *   the mail transport's host).
 *
 * @throws TypeError when `path` is not a field of the registry
 */
export function compareSeedWithStored(
  path: string,
  seedValue: unknown,
  storedValue: unknown,
  registry: PolicyRegistry = REALM_POLICY_REGISTRY
): SeedComparison {
  const entry = registry.field(path);
  if (entry === undefined) throw new TypeError(`${path} is not a field of the realm policies`);
  const { direction } = entry.field;
  if (
    isDeepStrictEqual(seedValue, storedValue) ||
    (isSetDirection(direction) && sameEntries(seedValue, storedValue))
  ) {
    return 'same';
  }
  if (directionKind(direction) === 'opaque') return 'different';
  // From the stored value to the environment's: a tightening means the
  // environment is the stricter one.
  return compareDirection(direction, storedValue, seedValue) === 'tightening'
    ? 'stricter'
    : 'looser';
}
