import type { EmailOptions, EmailProvider, EmailResult, MockProviderConfig } from '../../types';

/**
 * Check if running in test environment
 */
function isTestEnvironment(): boolean {
  return process.env['NODE_ENV'] === 'test' || process.env['VITEST'] === 'true';
}

/**
 * Mock email provider for testing and development
 *
 * This provider logs emails to the console instead of actually sending them.
 * Useful for development and testing environments.
 */
export class MockEmailProvider implements EmailProvider {
  private sentEmails: EmailOptions[] = [];
  private readonly logToConsole: boolean;

  constructor(options?: MockProviderConfig) {
    // Default: log to console unless in test environment
    this.logToConsole = options?.logToConsole ?? !isTestEnvironment();
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
    if (this.logToConsole) {
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
