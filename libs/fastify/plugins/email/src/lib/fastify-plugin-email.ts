import {
  constantTimeCompare,
  createEmailService,
  type EmailProvider,
  type EmailService,
  generateVerificationToken,
  hashToken,
  isValidTokenFormat,
  MockEmailProvider,
  ResendEmailProvider,
  type ResendProviderConfig,
  SmtpEmailProvider,
  type SmtpProviderConfig,
} from '@qauth/server-email';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import type {
  EmailPluginOptions,
  EmailProviderConfig,
  EmailProviderType,
  EmailVerificationTokenUtils,
} from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    emailService: EmailService;
    emailVerificationTokenUtils: EmailVerificationTokenUtils;
  }
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
  config?: EmailProviderConfig
): EmailProvider {
  switch (providerType) {
    case 'mock':
      return new MockEmailProvider();
    case 'resend': {
      if (!config || !('apiKey' in config)) {
        throw new Error('Resend provider requires apiKey in providerConfig');
      }
      return new ResendEmailProvider(config as ResendProviderConfig);
    }
    case 'smtp': {
      if (!config || !('host' in config)) {
        throw new Error('SMTP provider requires host, port, secure, and auth in providerConfig');
      }
      return new SmtpEmailProvider(config as SmtpProviderConfig);
    }
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
    fastify.decorate('emailVerificationTokenUtils', {
      generateVerificationToken,
      hashToken,
      isValidTokenFormat,
      constantTimeCompare,
    });

    fastify.log.debug({ provider: providerType }, 'Email plugin registered');
  },
  {
    name: '@qauth/fastify-plugin-email',
  }
);
