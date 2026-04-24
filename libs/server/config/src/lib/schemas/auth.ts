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

  /**
   * Maximum refresh token attempts per window
   */
  REFRESH_RATE_LIMIT: z.coerce.number().int().min(1).default(10),

  /**
   * Refresh token rate limit window in seconds (default: 60 = 1 minute)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  REFRESH_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum logout attempts per window
   */
  LOGOUT_RATE_LIMIT: z.coerce.number().int().min(1).default(20),

  /**
   * Logout rate limit window in seconds (default: 60 = 1 minute)
   * Note: Converted to milliseconds in route handlers (value * 1000)
   */
  LOGOUT_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum authorize attempts per window
   */
  AUTHORIZE_RATE_LIMIT: z.coerce.number().int().min(1).default(60),

  /**
   * Authorize rate limit window in seconds (default: 60 = 1 minute)
   */
  AUTHORIZE_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum token exchange attempts per window
   */
  TOKEN_RATE_LIMIT: z.coerce.number().int().min(1).default(30),

  /**
   * Token rate limit window in seconds (default: 60 = 1 minute)
   */
  TOKEN_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * Maximum token introspection attempts per window
   */
  INTROSPECT_RATE_LIMIT: z.coerce.number().int().min(1).default(30),

  /**
   * Introspect rate limit window in seconds (default: 60 = 1 minute)
   */
  INTROSPECT_RATE_WINDOW: z.coerce.number().int().min(1).default(60),
  /**
   * Maximum userinfo requests per window
   */
  USERINFO_RATE_LIMIT: z.coerce.number().int().min(1).default(60),
  /**
   * Userinfo rate limit window in seconds (default: 60 = 1 minute)
   */
  USERINFO_RATE_WINDOW: z.coerce.number().int().min(1).default(60),

  /**
   * HMAC secret used to sign the `__Host-qauth_session` cookie (issue #150).
   * Minimum 32 characters. In production this MUST be set explicitly —
   * the default value is test-only and is rejected in NODE_ENV=production
   * by downstream consumers if needed.
   */
  SESSION_COOKIE_SECRET: z
    .string()
    .min(32, 'SESSION_COOKIE_SECRET must be at least 32 characters')
    .default('dev-only-session-secret-change-me-1234567890abcdef'),

  /**
   * Browser session TTL in seconds (default 86400 = 24 hours, per issue #150).
   */
  SESSION_COOKIE_TTL: z.coerce
    .number()
    .int()
    .min(60)
    .default(24 * 60 * 60),

  /**
   * Whether to set the Secure attribute on the session cookie. Defaults true;
   * tests and local dev can set false to use plain HTTP. Production MUST
   * keep this true — the __Host- prefix will reject the cookie otherwise.
   */
  SESSION_COOKIE_SECURE: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),

  /**
   * Window (in days) after dynamic registration during which the consent
   * screen shows the "Newly registered" phishing-defense badge. Zero
   * disables the badge.
   */
  DYNAMIC_CLIENT_BADGE_DAYS: z.coerce.number().int().min(0).default(30),
});

/**
 * Auth environment configuration type
 */
export type AuthEnv = z.infer<typeof authEnvSchema>;
