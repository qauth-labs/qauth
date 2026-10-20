import type { ConfigKey, EnvDeprecationWarning } from './types';

/** An environment as `process.env` holds it. */
export type RawEnv = Readonly<Record<string, string | undefined>>;

/** The outcome of {@link applyKeyAliases}. */
export interface AliasedEnv {
  /**
   * A copy of the environment with every old name moved onto its current name.
   * The old names are not in it, so no schema can read one by mistake.
   */
  readonly env: RawEnv;
  /** One warning per old name the deployment still sets. */
  readonly deprecations: readonly EnvDeprecationWarning[];
  /** Current name → the old name its value was read from. */
  readonly sources: ReadonlyMap<string, string>;
}

/**
 * An old and a current name of the same key are set to different values.
 * The boot fails, because either value would override one of the operator's
 * two statements. The message names both variables.
 */
export class KeyAliasConflictError extends Error {
  constructor(readonly conflicts: readonly string[]) {
    super(conflicts.join(' '));
    this.name = 'KeyAliasConflictError';
  }
}

/**
 * Unset and blank are the same: `docker-compose.yml` forwards variables in the
 * `${VAR:-}` form, so an absent one reaches the process as `''`.
 */
function isSet(value: string | undefined): value is string {
  return value !== undefined && value.trim() !== '';
}

/**
 * Read every renamed key under its current name (ADR-018 §5).
 *
 * For each alias of each registry entry:
 *
 * - Only the old name is set: its value moves to the current name, with a
 *   deprecation warning.
 * - Both are set to the same value: the current name is used, with a
 *   deprecation warning.
 * - Both are set to different values: {@link KeyAliasConflictError}, naming
 *   both. Every conflict is reported at once.
 * - The old name is unset or blank: nothing happens.
 *
 * Neither the warnings nor the error show the value of a `secret` key.
 *
 * @throws KeyAliasConflictError when an old and a current name disagree
 */
export function applyKeyAliases(rawEnv: RawEnv, registry: readonly ConfigKey[]): AliasedEnv {
  const env: Record<string, string | undefined> = { ...rawEnv };
  const deprecations: EnvDeprecationWarning[] = [];
  const sources = new Map<string, string>();
  const conflicts: string[] = [];

  for (const key of registry) {
    for (const alias of key.aliases) {
      const oldValue = env[alias.name];
      delete env[alias.name];
      if (!isSet(oldValue)) continue;

      const current = env[key.name];
      if (!isSet(current)) {
        env[key.name] = oldValue;
        sources.set(key.name, alias.name);
        deprecations.push({
          variable: alias.name,
          replacement: key.name,
          message:
            `${alias.name} is deprecated since ${alias.deprecatedSince}. Rename it to ${key.name}. ` +
            'The old name still works during the deprecation window.',
        });
        continue;
      }

      // The value to compare against may itself come from an earlier alias.
      const currentName = sources.get(key.name) ?? key.name;
      if (current === oldValue) {
        deprecations.push({
          variable: alias.name,
          replacement: key.name,
          message: `${alias.name} is deprecated and duplicates ${currentName}. Remove ${alias.name}.`,
        });
        continue;
      }

      conflicts.push(
        (key.secret
          ? `${currentName} and ${alias.name} are set to different values. `
          : `${currentName}=${current} and ${alias.name}=${oldValue} disagree. `) +
          `${alias.name} is the deprecated name of ${key.name}. ` +
          `Remove it and keep only ${key.name}.`
      );
    }
  }

  if (conflicts.length > 0) {
    throw new KeyAliasConflictError(conflicts);
  }
  return { env, deprecations, sources };
}
