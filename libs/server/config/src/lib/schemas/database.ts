import { z } from 'zod';

/**
 * Database environment configuration schema
 * PostgreSQL connection and pool settings
 */
export const databaseEnvSchema = z.object({
  /**
   * PostgreSQL connection URL (required)
   */
  DATABASE_URL: z.url(),

  /**
   * Maximum number of connections in the pool
   */
  DB_POOL_MAX: z.coerce.number().int().min(1).default(20),

  /**
   * Minimum number of connections in the pool
   */
  DB_POOL_MIN: z.coerce.number().int().min(1).default(2),

  /**
   * Idle connection timeout in milliseconds
   */
  DB_POOL_IDLE_TIMEOUT: z.coerce.number().int().min(1).default(10000),

  /**
   * Connection timeout in milliseconds
   */
  DB_POOL_CONNECTION_TIMEOUT: z.coerce.number().int().min(1).default(2000),
});

/**
 * Database environment configuration type
 */
export type DatabaseEnv = z.infer<typeof databaseEnvSchema>;
