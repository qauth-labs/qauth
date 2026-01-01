import React from 'react';

import type {
  EmailOptions,
  EmailProvider,
  EmailResult,
  EmailService,
  EmailServiceConfig,
} from '../types';
import { renderEmail, renderEmailText } from './templates/render';
import { VerifyEmail } from './templates/verification-email';

/**
 * Create an email service with the given provider and configuration
 *
 * Uses the factory pattern to create an email service instance.
 * This allows for dependency injection and testing with mock providers.
 *
 * @param provider - Email provider implementation
 * @param config - Optional email service configuration
 * @returns Email service instance
 *
 * @example
 * ```typescript
 * import { MockEmailProvider } from './providers/mock.provider';
 *
 * const mockProvider = new MockEmailProvider();
 * const emailService = createEmailService(mockProvider, {
 *   defaultFrom: 'noreply@example.com',
 *   baseUrl: 'https://example.com',
 * });
 *
 * await emailService.sendVerificationEmail('user@example.com', 'token123');
 * ```
 */
export function createEmailService(
  provider: EmailProvider,
  config?: EmailServiceConfig
): EmailService {
  const defaultFrom = config?.defaultFrom;
  const baseUrl = config?.baseUrl;

  return {
    async sendVerificationEmail(
      to: string,
      token: string,
      options?: Partial<EmailOptions>
    ): Promise<EmailResult> {
      const verificationUrl = baseUrl ? `${baseUrl}/auth/verify?token=${token}` : `#token=${token}`;
      const expiresIn = '24 hours';

      const subject = options?.subject || 'Verify your email address';

      // Use custom text/html if provided, otherwise use React Email template
      let text = options?.text;
      let html = options?.html;

      if (!text && !html) {
        const template = React.createElement(VerifyEmail, {
          verificationUrl,
          expiresIn,
        });

        html = await renderEmail(template);
        text = await renderEmailText(template);
      }

      return provider.sendEmail({
        to,
        subject,
        text,
        html,
        from: options?.from || defaultFrom,
      });
    },
  };
}
