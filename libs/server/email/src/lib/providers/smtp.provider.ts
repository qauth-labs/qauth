import type { Transporter } from 'nodemailer';
import nodemailer from 'nodemailer';

import type { EmailOptions, EmailProvider, EmailResult, SmtpProviderConfig } from '../../types';
import {
  resolveSmtpDestination,
  type SmtpConnectionPolicy,
  STRICT_SMTP_CONNECTION_POLICY,
} from '../smtp-destination';

/**
 * SMTP email provider implementation.
 *
 * Each mail resolves the host and checks the address it connects to against
 * `config.connection` (#529, from the review of #937): a public unicast
 * address unless the operator allows the host, never a cloud metadata
 * address. The connection then dials that address, with the host name as its
 * TLS server name, so the certificate is checked against the name and DNS
 * cannot point the connection anywhere else. A connection that starts
 * without TLS (`secure: false`) must be upgraded with STARTTLS unless the
 * operator allows plaintext (`SMTP_ALLOW_PLAINTEXT`).
 */
export class SmtpEmailProvider implements EmailProvider {
  private readonly defaultFrom?: string;
  private readonly connection: SmtpConnectionPolicy;

  constructor(private readonly config: SmtpProviderConfig) {
    this.defaultFrom = config.fromAddress;
    this.connection = config.connection ?? STRICT_SMTP_CONNECTION_POLICY;
  }

  /** The transport of one mail, to the address its host resolves to now. */
  private async transporter(): Promise<Transporter> {
    const { address, servername } = await resolveSmtpDestination(this.config.host, this.connection);
    return nodemailer.createTransport({
      host: address,
      port: this.config.port,
      secure: this.config.secure,
      auth: this.config.auth,
      // A connection that starts in the clear must become TLS, unless the
      // operator allows a plaintext relay; a realm setting never can.
      requireTLS: this.config.secure ? false : !this.connection.allowPlaintext,
      ...(servername === undefined ? {} : { servername }),
      // The certificate is checked, against the host name when it is one.
      tls: {
        rejectUnauthorized: true,
        ...(servername === undefined ? {} : { servername }),
      },
    });
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

      const transporter = await this.transporter();
      const info = await transporter.sendMail({
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
