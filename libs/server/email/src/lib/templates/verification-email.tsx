import * as React from 'react';

import { DEFAULT_MAIL_BRAND } from '../engine-mail/brand';
import { LinkButton, MailFrame, Paragraph } from './engine/layout';

/**
 * Props for the VerifyEmail template
 */
export interface VerifyEmailProps {
  /**
   * Verification URL to include in the email
   */
  verificationUrl: string;
  /**
   * Expiration time description (e.g., "24 hours", "1 hour")
   */
  expiresIn: string;
}

/**
 * React Email template for email verification
 *
 * @param props - Template props
 * @returns React component
 */
export function VerifyEmail({ verificationUrl, expiresIn }: VerifyEmailProps) {
  return (
    <MailFrame
      brand={DEFAULT_MAIL_BRAND}
      preview="Verify your email address to complete your registration"
      title="Verify Your Email Address"
    >
      <Paragraph brand={DEFAULT_MAIL_BRAND}>
        Thank you for registering with QAuth. Please verify your email address by clicking the
        button below:
      </Paragraph>
      <LinkButton brand={DEFAULT_MAIL_BRAND} href={verificationUrl} label="Verify Email" />
      <Paragraph brand={DEFAULT_MAIL_BRAND}>
        This verification link will expire in {expiresIn}. If you did not create an account, you can
        safely ignore this email.
      </Paragraph>
    </MailFrame>
  );
}
