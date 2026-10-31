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
