/**
 * Email options for sending emails
 */
export interface EmailOptions {
  /** Recipient email address */
  to: string;
  /** Email subject */
  subject: string;
  /** Email body (plain text) */
  text?: string;
  /** Email body (HTML) */
  html?: string;
  /** Sender email address (optional, may be set by provider) */
  from?: string;
}

/**
 * Result of sending an email
 */
export interface EmailResult {
  /** Whether the email was sent successfully */
  success: boolean;
  /** Message ID from the email provider (if available) */
  messageId?: string;
  /** Error message if sending failed */
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
   * @param options - Email options (to, subject, text/html)
   * @returns Promise resolving to email result
   */
  sendEmail(options: EmailOptions): Promise<EmailResult>;
}
