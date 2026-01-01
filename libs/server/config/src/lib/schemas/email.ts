import { z } from 'zod';

/**
 * Email environment configuration schema
 */
export const emailEnvSchema = z.object({
  /**
   * Email provider type
   */
  EMAIL_PROVIDER: z.enum(['mock', 'resend', 'smtp']).default('mock'),

  /**
   * Default sender email address
   */
  EMAIL_FROM: z.string().email().optional(),

  /**
   * Base URL for email links (e.g., verification links)
   */
  EMAIL_BASE_URL: z.string().url().optional(),

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
  SMTP_SECURE: z
    .string()
    .transform((val) => val === 'true' || val === '1')
    .pipe(z.boolean())
    .default(false),

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
