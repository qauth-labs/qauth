import * as dotenv from 'dotenv';
import { z } from 'zod';

import { applyKeyAliases, type RawEnv } from './aliases';
import { experimentalSettingWarnings } from './experimental';
import type { ConfigKey, ConfigWarning, EnvDeprecationWarning } from './types';

/** The environment as the registry reads it. See {@link readConfiguredEnv}. */
export interface ConfiguredEnv {
  /** The environment with every renamed key under its current name. */
  readonly env: RawEnv;
  /** One warning per deprecated name the deployment still sets. */
  readonly deprecations: readonly EnvDeprecationWarning[];
  /** One warning per experimental key or value the deployment sets. */
  readonly experimental: readonly ConfigWarning[];
  /**
   * Validate {@link env} against a schema.
   *
   * When a value read from an old name fails validation, the issue names the
   * old name too, so the operator sees the variable they actually set.
   *
   * @throws ZodError if validation fails
   */
  parse<T extends z.ZodType>(schema: T): z.infer<T>;
}

/**
 * Read the process environment through the configuration key registry.
 *
 * Loads `.env` (variables already set win), moves every renamed key onto its
 * current name with {@link applyKeyAliases}, and collects the boot warnings
 * for deprecated names and experimental settings. The caller logs the
 * warnings once its logger exists.
 *
 * @param registry - the registry entries to apply, normally `CONFIG_KEY_REGISTRY`
 * @param source - the environment to read; `process.env`, after `.env` is
 *   loaded, when omitted
 * @throws KeyAliasConflictError when an old and a current name disagree
 *
 * @example
 * ```typescript
 * const configured = readConfiguredEnv(CONFIG_KEY_REGISTRY);
 * const env = configured.parse(envSchema);
 * for (const warning of configured.deprecations) log.warn(warning.message);
 * ```
 */
export function readConfiguredEnv(registry: readonly ConfigKey[], source?: RawEnv): ConfiguredEnv {
  if (source === undefined) {
    // Explicit, because dotenv 18 otherwise takes `override` from a
    // DOTENV_OVERRIDE variable, and variables already set must win.
    dotenv.config({ override: false });
  }
  const aliased = applyKeyAliases(source ?? process.env, registry);

  return {
    env: aliased.env,
    deprecations: aliased.deprecations,
    experimental: experimentalSettingWarnings(aliased.env, registry),
    parse<T extends z.ZodType>(schema: T): z.infer<T> {
      const result = schema.safeParse(aliased.env);
      if (result.success) {
        return result.data;
      }
      throw new z.ZodError(
        result.error.issues.map((issue) => {
          const key = issue.path[0];
          const oldName = typeof key === 'string' ? aliased.sources.get(key) : undefined;
          if (typeof key !== 'string' || oldName === undefined) {
            return issue;
          }
          return {
            ...issue,
            message: `${issue.message} (the value comes from ${oldName}, the deprecated name of ${key})`,
          };
        })
      );
    },
  };
}
