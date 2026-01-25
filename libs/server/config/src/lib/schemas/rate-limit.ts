import { z } from 'zod';

/**
 * Rate limiting environment configuration schema
 * Global rate limiting settings
 */
export const rateLimitEnvSchema = z.object({
  /**
   * Enable or disable rate limiting globally
   * Set to false to disable rate limiting (useful for development/testing)
   */
  RATE_LIMIT_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('true')
    .transform((val) => val === 'true' || val === '1'),

  /**
   * Maximum requests per window
   */
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),

  /**
   * Rate limit window in seconds
   */
  RATE_LIMIT_WINDOW: z.coerce.number().int().min(1).default(3600),

  /**
   * Health endpoint maximum requests per window
   * Health checks are typically more frequent, so higher limit
   */
  HEALTH_RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(1000),

  /**
   * Health endpoint rate limit window in seconds
   */
  HEALTH_RATE_LIMIT_WINDOW: z.coerce.number().int().min(1).default(60),
});

/**
 * Rate limit environment configuration type
 */
export type RateLimitEnv = z.infer<typeof rateLimitEnvSchema>;
