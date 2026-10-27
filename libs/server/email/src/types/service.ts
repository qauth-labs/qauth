import type { EmailOptions, EmailResult } from './core';

/**
 * Email service configuration
 */
export interface EmailServiceConfig {
  /** Default sender email address */
  defaultFrom?: string;
  /**
   * Lifetime of an email verification token, in seconds.
   *
   * Only affects the copy rendered in the email ("this link expires in ...").
   * Enforcement lives at the call sites, which derive `expiresAt` from the same
   * configuration value; this exists so the two cannot drift.
   *
   * @default 86400 (24 hours)
   */
  verificationTokenExpiry?: number;
}

/**
 * Where the link in a verification email points.
 *
 * Given per mail rather than once per service: a server with several realms
 * mails each account a link on its own realm's issuer (ADR-019 Decision 1).
 */
export interface VerificationLink {
  /**
   * The absolute URL the link starts at, with no trailing slash: the link is
   * `${baseUrl}/auth/verify?token=<token>`. The auth server passes the issuer of
   * the realm the account belongs to, never a URL from the request.
   */
  readonly baseUrl: string;
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
   * @param link - Where the verification link points
   * @param options - Optional additional email options
   * @returns Promise resolving to email result
   */
  sendVerificationEmail(
    to: string,
    token: string,
    link: VerificationLink,
    options?: Partial<EmailOptions>
  ): Promise<EmailResult>;

  /**
   * Tell the owner of an address that someone tried to register it again.
   *
   * Registration answers every address the same way, so this notice is how
   * the person who already has an account hears about the attempt. It carries
   * no link and no token.
   *
   * @param to - Recipient email address (the existing account's address)
   * @param options - Optional additional email options
   * @returns Promise resolving to email result
   */
  sendAccountExistsEmail(to: string, options?: Partial<EmailOptions>): Promise<EmailResult>;
}
