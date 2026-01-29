import {
  authEnvSchema,
  baseEnvSchema,
  databaseEnvSchema,
  emailEnvSchema,
  jwtEnvSchema,
  parseEnv,
  passwordEnvSchema,
  rateLimitEnvSchema,
  redisEnvSchema,
} from '@qauth/server-config';
import { z } from 'zod';

/**
 * Auth server environment schema
 * Composes all required schemas and adds app-specific configuration
 */
const envSchema = z.object({
  ...baseEnvSchema.shape,
  ...databaseEnvSchema.shape,
  ...redisEnvSchema.shape,
  ...passwordEnvSchema.shape,
  ...authEnvSchema.shape,
  ...rateLimitEnvSchema.shape,
  ...emailEnvSchema.shape,
  /**
   * CORS allowed origin (app-specific)
   */
  CORS_ORIGIN: z.string().optional(),
});

/**
 * Validated environment configuration
 */
export const env: z.infer<typeof envSchema> & z.infer<typeof jwtEnvSchema> = {
  ...parseEnv(envSchema),
  ...parseEnv(jwtEnvSchema),
};
