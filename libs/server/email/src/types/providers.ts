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
  /** Additional SMTP options (optional) */
  options?: {
    /** Require TLS */
    requireTLS?: boolean;
    /** Ignore TLS certificate errors (not recommended for production) */
    ignoreTLS?: boolean;
  };
}
