import {
  createEmailService,
  createMockEmailProvider,
  type EmailProvider,
  type EmailService,
  type EmailServiceConfig,
} from '@qauth/server-email';
import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

declare module 'fastify' {
  interface FastifyInstance {
    emailService: EmailService;
  }
}

/**
 * Email provider type
 */
export type EmailProviderType = 'mock' | 'resend' | 'smtp';

/**
 * Provider-specific configuration
 * This will be extended when resend/smtp providers are implemented
 */
export interface EmailProviderConfig {
  /**
   * Provider-specific configuration
   * For mock: no config needed
   * For resend: API key, etc. (future)
   * For smtp: host, port, auth, etc. (future)
   */
  [key: string]: unknown;
}

/**
 * Email plugin configuration options
 */
export interface EmailPluginOptions extends FastifyPluginOptions {
  /**
   * Email provider type (mock, resend, smtp)
   * Default: 'mock'
   */
  provider?: EmailProviderType;
  /**
   * Provider-specific configuration
   * Optional - depends on provider type
   */
  providerConfig?: EmailProviderConfig;
  /**
   * Email service configuration
   * Optional - missing values will use defaults
   */
  serviceConfig?: Partial<EmailServiceConfig>;
}

/**
 * Create an email provider based on the provider type
 *
 * @param providerType - Type of provider to create
 * @param config - Provider-specific configuration
 * @returns Email provider instance
 */
function createProvider(
  providerType: EmailProviderType = 'mock',
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  _config?: EmailProviderConfig
): EmailProvider {
  switch (providerType) {
    case 'mock':
      return createMockEmailProvider();
    case 'resend':
      // TODO: Implement Resend provider
      throw new Error('Resend provider not yet implemented');
    case 'smtp':
      // TODO: Implement SMTP provider
      throw new Error('SMTP provider not yet implemented');
    default:
      throw new Error(`Unknown email provider type: ${providerType}`);
  }
}

/**
 * Fastify plugin for email service
 * Decorates fastify instance with emailService
 *
 * @example
 * ```typescript
 * await fastify.register(emailPlugin, {
 *   provider: 'mock',
 *   serviceConfig: {
 *     defaultFrom: 'noreply@example.com',
 *     baseUrl: 'https://example.com',
 *   },
 * });
 *
 * // Use in routes
 * await fastify.emailService.sendVerificationEmail('user@example.com', token);
 * ```
 */
export const emailPlugin = fp<EmailPluginOptions>(
  async (fastify: FastifyInstance, options: EmailPluginOptions) => {
    const providerType = options.provider || 'mock';
    const provider = createProvider(providerType, options.providerConfig);
    const emailService = createEmailService(provider, options.serviceConfig);

    fastify.decorate('emailService', emailService);

    fastify.log.debug({ provider: providerType }, 'Email plugin registered');
  },
  {
    name: '@qauth/fastify-plugin-email',
  }
);
