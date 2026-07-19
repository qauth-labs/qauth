import {
  authEnvSchema,
  baseEnvSchema,
  cryptoEnvSchema,
  databaseEnvSchema,
  DEV_SESSION_COOKIE_SECRET_DEFAULT,
  emailEnvSchema,
  federationEnvSchema,
  jwtEnvSchema,
  observabilityEnvSchema,
  parseEnv,
  passwordEnvSchema,
  rateLimitEnvSchema,
  redisEnvSchema,
} from '@qauth-labs/server-config';
import { z } from 'zod';

/**
 * Auth server environment schema
 * Composes all required schemas and adds app-specific configuration
 */
const envSchema = z
  .object({
    ...baseEnvSchema.shape,
    ...databaseEnvSchema.shape,
    ...redisEnvSchema.shape,
    ...passwordEnvSchema.shape,
    ...authEnvSchema.shape,
    ...rateLimitEnvSchema.shape,
    ...emailEnvSchema.shape,
    ...observabilityEnvSchema.shape,
    // Wallet federation (ADR-004, #232): WALLET_FEDERATION_ENABLED, default off.
    ...federationEnvSchema.shape,
    /**
     * CORS allowed origin (app-specific). When unset in `production` the
     * server denies all cross-origin requests (fail-closed); in non-production
     * it falls back to `*` for local dev convenience.
     */
    CORS_ORIGIN: z.string().optional(),
    /**
     * Expose the Swagger UI at `/docs`. Defaults to `true` outside
     * `production` and `false` in `production` so the API surface is not
     * advertised to unauthenticated callers in a hardened deployment. An
     * operator may opt back in by setting `ENABLE_SWAGGER=true` (e.g. for an
     * internal docs mirror).
     */
    ENABLE_SWAGGER: z.coerce
      .string()
      .optional()
      .transform((v) => (v === undefined ? undefined : v.toLowerCase() === 'true')),
  })
  .superRefine((env, ctx) => {
    // F-12 — reject the dev-default SESSION_COOKIE_SECRET in production. The
    // schema's own `.default()` ships a test-only value; without this guard a
    // production deployment that forgets to set the env var silently signs
    // session cookies with a publicly-known secret.
    if (
      env.NODE_ENV === 'production' &&
      env.SESSION_COOKIE_SECRET === DEV_SESSION_COOKIE_SECRET_DEFAULT
    ) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['SESSION_COOKIE_SECRET'],
        message:
          'SESSION_COOKIE_SECRET must be set to a strong secret of at least 32 characters in production (the dev default is not allowed).',
      });
    }
  });

/**
 * Validated environment configuration
 */
const parsedEnv = parseEnv(envSchema);
export const env: z.infer<typeof envSchema> &
  z.infer<typeof jwtEnvSchema> &
  z.infer<typeof cryptoEnvSchema> = {
  ...parsedEnv,
  ...parseEnv(jwtEnvSchema),
  // Crypto / PQC signing config (ADR-005): SIGNING_ALGORITHM_MODE (#243),
  // HYBRID_SIGNING_ENABLED + ML-DSA key (#245), with fail-fast coupling.
  ...parseEnv(cryptoEnvSchema),
  // resolved after parse: ENABLE_SWAGGER defaults to NODE_ENV !== 'production'
  ENABLE_SWAGGER: parsedEnv.ENABLE_SWAGGER ?? parsedEnv.NODE_ENV !== 'production',
};
