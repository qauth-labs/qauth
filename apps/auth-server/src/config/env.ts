import {
  CONFIG_KEY_REGISTRY,
  cryptoEnvSchema,
  type EnvDeprecationWarning,
  jwtEnvSchema,
  readConfiguredEnv,
} from '@qauth-labs/server-config';
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
