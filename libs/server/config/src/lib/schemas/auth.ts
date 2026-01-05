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
   * System OAuth client ID (defaults to "system")
   * Used for direct login operations (not OAuth flow)
   */
  SYSTEM_CLIENT_ID: z.string().optional().default('system'),

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

  /**
   * Maximum resend verification attempts per window (per-IP)
   */
  RESEND_VERIFICATION_RATE_LIMIT: z.coerce.number().int().min(1).default(100),

  /**
   * Resend verification rate limit window in seconds (default: 60 = 1 minute)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  RESEND_VERIFICATION_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum resend verification attempts per email address per window
   * Prevents inbox bombing attacks
   */
  RESEND_VERIFICATION_EMAIL_LIMIT: z.coerce.number().int().min(1).default(3),

  /**
   * Per-email resend verification rate limit window in seconds (default: 3600 = 1 hour)
   */
  RESEND_VERIFICATION_EMAIL_WINDOW: z.coerce.number().int().min(1).default(3600),

  /**
   * Minimum interval between resend requests to same email in seconds (default: 60)
   * Prevents rapid repeated requests
   */
  RESEND_VERIFICATION_MIN_INTERVAL: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum login attempts per window
   */
  LOGIN_RATE_LIMIT: z.coerce.number().int().min(1).default(5),

  /**
   * Login rate limit window in seconds (default: 900 = 15 minutes)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  LOGIN_RATE_WINDOW: z.coerce.number().int().min(1).default(900),
});

/**
 * Auth environment configuration type
 */
export type AuthEnv = z.infer<typeof authEnvSchema>;
