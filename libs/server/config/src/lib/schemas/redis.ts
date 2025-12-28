import { z } from 'zod';

/**
 * Redis environment configuration schema
 * Redis connection and pool settings
 */
export const redisEnvSchema = z.object({
  /**
   * Redis connection URL (optional, takes precedence over individual settings)
   */
  REDIS_URL: z.url().optional(),

  /**
   * Redis host address (used if REDIS_URL is not set)
   */
  REDIS_HOST: z.string().optional(),

  /**
   * Redis port number (used if REDIS_URL is not set)
   */
  REDIS_PORT: z.coerce.number().int().min(1).max(65535).optional(),

  /**
   * Redis password (optional)
   */
  REDIS_PASSWORD: z.string().optional(),

  /**
   * Redis database number
   */
  REDIS_DB: z.coerce.number().int().min(0).optional(),

  /**
   * Maximum retries per request
   */
  REDIS_MAX_RETRIES: z.coerce.number().int().min(1).default(3),

  /**
   * Retry delay on failover in milliseconds
   */
  REDIS_RETRY_DELAY: z.coerce.number().int().min(1).default(1000),

  /**
   * Connection timeout in milliseconds
   */
  REDIS_CONNECTION_TIMEOUT: z.coerce.number().int().min(1).default(10000),

  /**
   * Command timeout in milliseconds
   */
  REDIS_COMMAND_TIMEOUT: z.coerce.number().int().min(1).default(5000),
});

/**
 * Redis environment configuration type
 */
export type RedisEnv = z.infer<typeof redisEnvSchema>;
