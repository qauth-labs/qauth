import type { Transporter } from 'nodemailer';
import nodemailer from 'nodemailer';

import type { EmailOptions, EmailProvider, EmailResult, SmtpProviderConfig } from '../../types';

/**
 * SMTP email provider implementation
 */
export class SmtpEmailProvider implements EmailProvider {
  private readonly transporter: Transporter;
  private readonly defaultFrom?: string;

  constructor(config: SmtpProviderConfig) {
    this.transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.auth,
      requireTLS: config.options?.requireTLS,
      ignoreTLS: config.options?.ignoreTLS,
    });
    this.defaultFrom = config.fromAddress;
  }

  /**
   * Send an email via SMTP
   *
   * @param options - Email options
   * @returns Promise resolving to email result
   */
  async sendEmail(options: EmailOptions): Promise<EmailResult> {
    try {
      const from = options.from || this.defaultFrom;
      if (!from) {
        return {
          success: false,
          error: 'From address is required. Set it in options or provider config.',
        };
      }

      // Validate that at least html or text is provided
      if (!options.html && !options.text) {
        return {
          success: false,
          error: 'Either html or text content must be provided',
        };
      }

      const info = await this.transporter.sendMail({
        from,
        to: options.to,
        subject: options.subject,
        text: options.text,
        html: options.html,
      });

      return {
        success: true,
        messageId: info.messageId,
      };
    } catch (error) {
      // Handle connection errors
      if (error instanceof Error) {
        const isConnectionError =
          error.message.includes('ECONNREFUSED') ||
          error.message.includes('ETIMEDOUT') ||
          error.message.includes('ENOTFOUND') ||
          error.message.includes('authentication failed') ||
          error.message.includes('Invalid login');

        if (isConnectionError) {
          return {
            success: false,
            error: `SMTP connection error: ${error.message}`,
          };
        }
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }
}
