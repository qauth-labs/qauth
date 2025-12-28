import { z } from 'zod';

/**
 * Rate limiting environment configuration schema
 * Global rate limiting settings
 */
export const rateLimitEnvSchema = z.object({
  /**
   * Maximum requests per window
   */
  RATE_LIMIT_MAX: z.coerce.number().int().min(1).default(100),

  /**
   * Rate limit window in seconds
   */
  RATE_LIMIT_WINDOW: z.coerce.number().int().min(1).default(3600),
});

/**
 * Rate limit environment configuration type
 */
export type RateLimitEnv = z.infer<typeof rateLimitEnvSchema>;
