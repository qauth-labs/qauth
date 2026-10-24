import {
  CONFIG_KEY_REGISTRY,
  type ConfigWarning,
  cryptoEnvSchema,
  type EnvDeprecationWarning,
  jwtEnvSchema,
  readConfiguredEnv,
} from '@qauth-labs/server-config';
import { switchesExperimentalFeature } from '@qauth-labs/shared-stability';
import { z } from 'zod';

import { envSchema } from './env-schema';

/**
 * The process environment, read through the configuration key registry.
 *
 * A renamed key set under its old name (`REQUIRE_EMAIL_VERIFIED`) arrives
 * under its current name (`REQUIRE_VERIFIED_ACCOUNT`), and the old name is
 * gone, so no reader can consult it instead. When the two names disagree the
 * boot fails here, naming both.
 */
const configured = readConfiguredEnv(CONFIG_KEY_REGISTRY);

/**
 * Validated environment configuration
 */
const parsedEnv = configured.parse(envSchema);

/**
 * Deprecated configuration names this deployment still sets. `main.ts` logs
 * each one at boot, once the logger exists.
 */
export const envDeprecationWarnings: readonly EnvDeprecationWarning[] = configured.deprecations;

/** The tier of each registered key, to tell an experimental key from one with experimental values. */
const keyTiers = new Map(CONFIG_KEY_REGISTRY.map((key) => [key.name, key.tier]));

/**
 * Experimental keys and values this deployment sets (ADR-018 §5). `main.ts`
 * logs each one at boot, once the logger exists.
 *
 * The switch of a built item of the experimental-feature registry is left
 * out: its item warns instead, once the item is on, with the item's id and
 * docs link (`logExperimentalFeatures`, called from `app.ts`). So a
 * deployment sees one line per experimental feature, not two. Another
 * experimental value of the same key keeps its own warning.
 */
export const envExperimentalWarnings: readonly ConfigWarning[] = configured.experimental.filter(
  (warning) =>
    !switchesExperimentalFeature({
      key: warning.variable,
      value: configured.env[warning.variable],
      experimentalKey: keyTiers.get(warning.variable) === 'experimental',
    })
);

/**
 * The app's env.
 */
export const env: z.infer<typeof envSchema> &
  z.infer<typeof jwtEnvSchema> &
  z.infer<typeof cryptoEnvSchema> = {
  ...parsedEnv,
  ...configured.parse(jwtEnvSchema),
  // Crypto / PQC signing config (ADR-005): SIGNING_ALGORITHM_MODE (#243),
  // HYBRID_SIGNING_ENABLED + ML-DSA key (#245), with fail-fast coupling.
  ...configured.parse(cryptoEnvSchema),
  // resolved after parse: ENABLE_SWAGGER defaults to NODE_ENV !== 'production'
  ENABLE_SWAGGER: parsedEnv.ENABLE_SWAGGER ?? parsedEnv.NODE_ENV !== 'production',
};
