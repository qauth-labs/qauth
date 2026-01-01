import type { EmailOptions, EmailResult } from './core';

/**
 * Email service configuration
 */
export interface EmailServiceConfig {
  /** Default sender email address */
  defaultFrom?: string;
  /** Base URL for verification links (optional) */
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
