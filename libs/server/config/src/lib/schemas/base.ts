import { z } from 'zod';

/**
 * Base server environment configuration schema
 * Common settings for all server applications
 */
export const baseEnvSchema = z.object({
  /**
   * Node environment
   */
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),

  /**
   * Server host address
   */
  HOST: z.string().default('0.0.0.0'),

  /**
   * Server port number
   */
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  /**
   * Logging level
   */
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),

  /**
   * Vitest test environment flag
   */
  VITEST: z.string().optional(),
});

/**
 * Base environment configuration type
 */
export type BaseEnv = z.infer<typeof baseEnvSchema>;
