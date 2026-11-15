import * as React from 'react';

import { DEFAULT_MAIL_BRAND, type MailBrand } from '../engine-mail/brand';
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
  /**
   * The brand the mail is named after: the realm's sender name's
   * (`EmailServiceConfig.brand`).
   *
   * @default DEFAULT_MAIL_BRAND (QAuth's)
   */
  brand?: MailBrand;
}

/**
 * React Email template for email verification
 *
 * @param props - Template props
 * @returns React component
 */
export function VerifyEmail({
  verificationUrl,
  expiresIn,
  brand = DEFAULT_MAIL_BRAND,
}: VerifyEmailProps) {
  return (
    <MailFrame
      brand={brand}
      preview="Verify your email address to complete your registration"
      title="Verify Your Email Address"
    >
      <Paragraph brand={brand}>
        Thank you for registering with {brand.name}. Please verify your email address by clicking
        the button below:
      </Paragraph>
      <LinkButton brand={brand} href={verificationUrl} label="Verify Email" />
      <Paragraph brand={brand}>
        This verification link will expire in {expiresIn}. If you did not create an account, you can
        safely ignore this email.
      </Paragraph>
    </MailFrame>
  );
}
