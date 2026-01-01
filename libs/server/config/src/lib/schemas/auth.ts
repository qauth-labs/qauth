import { z } from 'zod';

/**
 * Authentication environment configuration schema
 * Auth-specific settings
 */
export const authEnvSchema = z.object({
  /**
   * Default realm name for new installations
   */
  DEFAULT_REALM_NAME: z.string().min(1).default('master'),

  /**
   * Maximum registration attempts per window
   */
  REGISTRATION_RATE_LIMIT: z.coerce.number().int().min(1).default(3),

  /**
   * Registration rate limit window in seconds
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  REGISTRATION_RATE_WINDOW: z.coerce.number().int().min(1).default(3600),

  /**
   * Maximum email verification attempts per window
   */
  VERIFICATION_RATE_LIMIT: z.coerce.number().int().min(1).default(10),

  /**
   * Email verification rate limit window in seconds (default: 900 = 15 minutes)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  VERIFICATION_RATE_WINDOW: z.coerce.number().int().min(1).default(900),
});

/**
 * Auth environment configuration type
 */
export type AuthEnv = z.infer<typeof authEnvSchema>;
