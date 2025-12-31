import { baseEnvSchema, parseEnv } from '@qauth/server-config';

/**
 * Email options for sending emails
 */
export interface EmailOptions {
  /**
   * Recipient email address
   */
  to: string;
  /**
   * Email subject
   */
  subject: string;
  /**
   * Email body (plain text)
   */
  text?: string;
  /**
   * Email body (HTML)
   */
  html?: string;
  /**
   * Sender email address (optional, may be set by provider)
   */
  from?: string;
}

/**
 * Result of sending an email
 */
export interface EmailResult {
  /**
   * Whether the email was sent successfully
   */
  success: boolean;
  /**
   * Message ID from the email provider (if available)
   */
  messageId?: string;
  /**
   * Error message if sending failed
   */
  error?: string;
}

/**
 * Email provider interface (verification-agnostic)
 *
 * This interface is designed to be generic and can be used for
 * any type of email (verification, password reset, notifications, etc.)
 */
export interface EmailProvider {
  /**
   * Send an email
   *
   * @param options - Email options (to, subject, text/html)
   * @returns Promise resolving to email result
   */
  sendEmail(options: EmailOptions): Promise<EmailResult>;
}

/**
 * Email service configuration
 */
export interface EmailServiceConfig {
  /**
   * Default sender email address
   */
  defaultFrom?: string;
  /**
   * Base URL for verification links (optional)
   */
  baseUrl?: string;
}

/**
 * Email service interface
 *
 * Provides domain-specific email methods built on top of the generic EmailProvider
 */
export interface EmailService {
  /**
   * Send a verification email
   *
   * @param to - Recipient email address
   * @param token - Verification token to include in the email
   * @param options - Optional additional email options
   * @returns Promise resolving to email result
   */
  sendVerificationEmail(
    to: string,
    token: string,
    options?: Partial<EmailOptions>
  ): Promise<EmailResult>;
}

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
 * const mockProvider = createMockEmailProvider();
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
      const verificationUrl = baseUrl ? `${baseUrl}/auth/verify?token=${token}` : undefined;

      const subject = options?.subject || 'Verify your email address';
      const text =
        options?.text ||
        `Please verify your email address by clicking the following link:\n\n${verificationUrl || `Use token: ${token}`}\n\nThis link will expire in 24 hours.`;
      const html =
        options?.html ||
        `<p>Please verify your email address by clicking the following link:</p><p><a href="${verificationUrl || `#token=${token}`}">Verify Email</a></p><p>This link will expire in 24 hours.</p>`;

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

/**
 * Mock email provider for testing and development
 *
 * This provider logs emails to the console instead of actually sending them.
 * Useful for development and testing environments.
 */
export class MockEmailProvider implements EmailProvider {
  private sentEmails: EmailOptions[] = [];
  private readonly isTestEnv: boolean;

  constructor() {
    const env = parseEnv(baseEnvSchema);
    this.isTestEnv = env.NODE_ENV === 'test' || !!env.VITEST;
  }

  /**
   * Send an email (mock implementation)
   *
   * Logs the email to console and stores it in memory for testing.
   *
   * @param options - Email options
   * @returns Promise resolving to success result
   */
  async sendEmail(options: EmailOptions): Promise<EmailResult> {
    // Store email for testing purposes
    this.sentEmails.push(options);

    // Log to console in development (not in test/vitest environment)
    if (!this.isTestEnv) {
      console.log('[MockEmailProvider] Email sent:', {
        to: options.to,
        subject: options.subject,
        from: options.from,
        text: options.text ? options.text.substring(0, 100) + '...' : undefined,
        html: options.html ? '[HTML content]' : undefined,
      });
    }

    return {
      success: true,
      messageId: `mock-${Date.now()}-${Math.random().toString(36).substring(7)}`,
    };
  }

  /**
   * Get all sent emails (for testing)
   *
   * @returns Array of sent email options
   */
  getSentEmails(): EmailOptions[] {
    return [...this.sentEmails];
  }

  /**
   * Clear sent emails history (for testing)
   */
  clearSentEmails(): void {
    this.sentEmails = [];
  }
}

/**
 * Create a mock email provider instance
 *
 * @returns Mock email provider
 */
export function createMockEmailProvider(): MockEmailProvider {
  return new MockEmailProvider();
}
