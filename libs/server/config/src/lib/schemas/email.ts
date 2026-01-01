import { z } from 'zod';

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
   */
  EMAIL_VERIFICATION_INVALIDATE_EXISTING_ON_RESEND: z.coerce.boolean().default(true),

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
   * Base URL for email links (e.g., verification links)
   */
  EMAIL_BASE_URL: z.url(),

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
   * SMTP secure connection (TLS/SSL)
   */
  SMTP_SECURE: z.coerce.boolean().default(true),

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
