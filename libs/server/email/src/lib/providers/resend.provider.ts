import * as crypto from 'node:crypto';

import type { CreateEmailOptions } from 'resend';
import { Resend } from 'resend';

import type { EmailOptions, EmailProvider, EmailResult, ResendProviderConfig } from '../../types';

/**
 * Maximum number of retry attempts for transient failures
 */
const MAX_RETRIES = 3;

/**
 * Resend email provider implementation
 */
export class ResendEmailProvider implements EmailProvider {
  private readonly resend: Resend;
  private readonly defaultFrom?: string;

  constructor(config: ResendProviderConfig) {
    this.resend = new Resend(config.apiKey);
    this.defaultFrom = config.fromAddress;
  }

  /**
   * Generate a content-based idempotency key
   *
   * This ensures the same email content produces the same key,
   * preventing duplicate sends during retries.
   */
  private generateIdempotencyKey(options: EmailOptions, from: string): string {
    const content = `${from}-${options.to}-${options.subject}-${options.html || ''}-${options.text || ''}`;
    return crypto.createHash('sha256').update(content).digest('hex').substring(0, 32);
  }

  /**
   * Check if an error is retryable (transient failure)
   */
  private isRetryableError(error: Error): boolean {
    const lowerMessage = error.message.toLowerCase();
    return (
      lowerMessage.includes('network') ||
      lowerMessage.includes('timeout') ||
      lowerMessage.includes('rate limit') ||
      lowerMessage.includes('429') ||
      lowerMessage.includes('econnreset') ||
      lowerMessage.includes('econnrefused')
    );
  }

  /**
   * Internal method to send email via Resend API
   */
  private async sendEmailInternal(
    options: EmailOptions,
    from: string,
    idempotencyKey: string
  ): Promise<EmailResult> {
    const emailPayload = {
      from,
      to: options.to,
      subject: options.subject,
      ...(options.html && { html: options.html }),
      ...(options.text && { text: options.text }),
    };

    const result = await this.resend.emails.send(emailPayload as CreateEmailOptions, {
      idempotencyKey,
    });

    if (result.error) {
      return {
        success: false,
        error: result.error.message || 'Failed to send email via Resend',
      };
    }

    return {
      success: true,
      messageId: result.data?.id,
    };
  }

  /**
   * Send an email via Resend API
   *
   * @param options - Email options
   * @returns Promise resolving to email result
   */
  async sendEmail(options: EmailOptions): Promise<EmailResult> {
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

    // Generate content-based idempotency key
    const idempotencyKey = this.generateIdempotencyKey(options, from);

    try {
      return await this.sendEmailInternal(options, from, idempotencyKey);
    } catch (error) {
      // Handle retryable errors
      if (error instanceof Error && this.isRetryableError(error)) {
        let lastError = error;

        for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
          // Exponential backoff: 2s, 4s, 8s
          await new Promise((resolve) => setTimeout(resolve, Math.pow(2, attempt) * 1000));

          try {
            // Same idempotency key ensures no duplicate if previous attempt actually succeeded
            return await this.sendEmailInternal(options, from, idempotencyKey);
          } catch (retryError) {
            lastError = retryError instanceof Error ? retryError : new Error(String(retryError));
          }
        }

        return {
          success: false,
          error: `Failed to send email after ${MAX_RETRIES} retries: ${lastError.message}`,
        };
      }

      return {
        success: false,
        error: error instanceof Error ? error.message : 'Unknown error occurred',
      };
    }
  }
}
