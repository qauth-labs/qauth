import { z } from 'zod';

/** Blank is read as unset, since Docker Compose passes an absent variable as `''`. */
function blankAsUnset(value: unknown): unknown {
  return typeof value === 'string' && value.trim() === '' ? undefined : value;
}

/**
 * Email environment configuration schema
 */
export const emailEnvSchema = z.object({
  /**
   * Email verification token expiry in seconds (default: 86400 = 24 hours)
   */
  EMAIL_VERIFICATION_TOKEN_EXPIRY: z.coerce.number().int().min(3600).default(86400),

  /**
   * Whether to invalidate existing tokens when resending verification email
   * If true, only the latest token is valid (more secure)
   * If false, multiple tokens can be active (user can use any valid token)
   *
   * Uses `z.enum(['true', 'false'])` rather than `z.coerce.boolean()`, which
   * treats ANY non-empty string as `true` (so `"false"` → `true`, inverting
   * operator intent). Mirrors the boolean-flag pattern in `auth.ts`.
   */
  EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),

  /**
   * Email provider type
   */
  EMAIL_PROVIDER: z.enum(['mock', 'resend', 'smtp']).default('mock'),

  /**
   * Default sender email address (required)
   */
  EMAIL_FROM_ADDRESS: z.email(),

  /**
   * Default sender name (default: 'QAuth')
   */
  EMAIL_FROM_NAME: z.string().default('QAuth'),

  /**
   * Optional and not read since 0.2.0 (#490): a link in mail starts at the
   * issuer of the account's realm. Still accepted, so a deployment that sets it
   * keeps starting; the auth server warns at boot when it names another base
   * than `JWT_ISSUER`. Blank is unset.
   */
  EMAIL_BASE_URL: z.preprocess(blankAsUnset, z.url().optional()),

  /**
   * Resend API key (required if EMAIL_PROVIDER is 'resend')
   */
  RESEND_API_KEY: z.string().optional(),

  /**
   * SMTP host (required if EMAIL_PROVIDER is 'smtp')
   */
  SMTP_HOST: z.string().optional(),

  /**
   * SMTP port (required if EMAIL_PROVIDER is 'smtp')
   */
  SMTP_PORT: z.coerce.number().int().min(1).max(65535).optional(),

  /**
   * SMTP secure connection (TLS/SSL).
   *
   * Uses `z.enum(['true', 'false'])` rather than `z.coerce.boolean()`, which
   * treats ANY non-empty string as `true` (so `"false"` → `true`) — here that
   * would force TLS on even when an operator explicitly disabled it.
   */
  SMTP_SECURE: z
    .enum(['true', 'false'])
    .default('true')
    .transform((v) => v === 'true'),

  /**
   * SMTP username (required if EMAIL_PROVIDER is 'smtp')
   */
  SMTP_USER: z.string().optional(),

  /**
   * SMTP password (required if EMAIL_PROVIDER is 'smtp')
   */
  SMTP_PASSWORD: z.string().optional(),
});

/**
 * Email environment configuration type
 */
export type EmailEnv = z.infer<typeof emailEnvSchema>;
