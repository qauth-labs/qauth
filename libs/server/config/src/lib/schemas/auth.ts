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
   */
  REGISTRATION_RATE_WINDOW: z.coerce.number().int().min(1).default(3600),
});

/**
 * Auth environment configuration type
 */
export type AuthEnv = z.infer<typeof authEnvSchema>;
