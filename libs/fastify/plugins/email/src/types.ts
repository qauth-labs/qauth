import type {
  EmailServiceConfig,
  ResendProviderConfig,
  SmtpProviderConfig,
} from '@qauth/server-email';
import type { FastifyPluginOptions } from 'fastify';

/**
 * Email provider type
 */
export type EmailProviderType = 'mock' | 'resend' | 'smtp';

/**
 * Provider-specific configuration
 * Union type for different provider configurations
 */
export type EmailProviderConfig = ResendProviderConfig | SmtpProviderConfig | Record<string, never>;

/**
 * Email plugin configuration options
 */
export interface EmailPluginOptions extends FastifyPluginOptions {
  /** Email provider type (mock, resend, smtp) @default 'mock' */
  provider?: EmailProviderType;
  /** Provider-specific configuration (optional, depends on provider type) */
  providerConfig?: EmailProviderConfig;
  /** Email service configuration (optional, missing values will use defaults) */
  serviceConfig?: Partial<EmailServiceConfig>;
}
