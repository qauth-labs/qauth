/**
 * An image the mail carries itself, shown in the HTML through
 * `<img src="cid:{contentId}">` (RFC 2392). Nothing is fetched when the mail
 * is opened.
 */
export interface EmailInlineImage {
  /** The Content-ID the HTML names after `cid:`, in the `id@domain` form. */
  readonly contentId: string;
  readonly filename: string;
  readonly contentType: string;
  readonly content: Buffer;
}

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
  /** Images the HTML shows through `cid:`, sent as inline attachments. */
  inlineImages?: readonly EmailInlineImage[];
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
