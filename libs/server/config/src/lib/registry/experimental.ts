import type { RawEnv } from './aliases';
import type { ConfigKey, ConfigWarning } from './types';

/** What every experimental warning tells the operator (ADR-018 §5). */
const EXPERIMENTAL_TERMS =
  'It may change in any release, without a deprecation window. See the configuration page.';

/**
 * The boot warnings ADR-018 §5 requires: one for each experimental key that is
 * set, and one for each key set to one of its experimental values.
 *
 * Pass the environment after {@link applyKeyAliases}, so a key set under an
 * old name warns too. Unset and blank are the same and never warn. The
 * warning for a `secret` key does not show its value.
 */
export function experimentalSettingWarnings(
  env: RawEnv,
  registry: readonly ConfigKey[]
): readonly ConfigWarning[] {
  const warnings: ConfigWarning[] = [];

  for (const key of registry) {
    const value = env[key.name]?.trim();
    if (value === undefined || value === '') continue;

    if (key.tier === 'experimental') {
      warnings.push({
        variable: key.name,
        message: `${key.name} is experimental. ${EXPERIMENTAL_TERMS}`,
      });
    } else if (key.experimentalValues.includes(value)) {
      warnings.push({
        variable: key.name,
        message: key.secret
          ? `${key.name} is set to an experimental value. ${EXPERIMENTAL_TERMS}`
          : `${key.name}=${value} is experimental. ${EXPERIMENTAL_TERMS}`,
      });
    }
  }

  return warnings;
}
