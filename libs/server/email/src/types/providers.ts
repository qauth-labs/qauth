import type { SmtpConnectionPolicy } from '../lib/smtp-destination';

/**
 * Configuration for Mock email provider
 */
export interface MockProviderConfig {
  /**
   * Whether to log emails to console
   * @default true in non-test environments
   */
  logToConsole?: boolean;
}

/**
 * Configuration for Resend email provider
 */
export interface ResendProviderConfig {
  /** Resend API key */
  apiKey: string;
  /** Default sender email address */
  fromAddress?: string;
}

/**
 * Configuration for SMTP email provider
 */
export interface SmtpProviderConfig {
  /** SMTP host */
  host: string;
  /** SMTP port */
  port: number;
  /** Use secure connection (TLS/SSL) */
  secure: boolean;
  /** SMTP authentication */
  auth: {
    /** SMTP username */
    user: string;
    /** SMTP password */
    pass: string;
  };
  /** Default sender email address */
  fromAddress?: string;
  /**
   * Where the connection may go and whether it may stay plaintext: the
   * operator's switches (`SMTP_ALLOWED_HOSTS`, `SMTP_ALLOW_PLAINTEXT`).
   * Strict when absent: public addresses only, and STARTTLS required.
   */
  connection?: SmtpConnectionPolicy;
}
