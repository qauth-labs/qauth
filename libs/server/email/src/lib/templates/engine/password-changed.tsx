import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, Paragraph } from './layout';

export interface PasswordChangedEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
}

/**
 * "Your password was changed" (PRO-14, #637; ADR-017 Decision 8, NIST SP
 * 800-63B-4 §4.2.3): a reset or a change of the password. It carries no link
 * and no secret, so a person who did not make the change starts the reset
 * from the sign-in page themselves.
 */
export function PasswordChangedEmail({ brand, baseUrl }: PasswordChangedEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="The password of your account was changed"
      title="Your password was changed"
    >
      <Paragraph brand={brand}>
        The password of the account that uses this email address was just changed.
      </Paragraph>
      <Paragraph brand={brand}>
        If you made this change, there is nothing else to do. If you did not, someone else may have
        access to this mailbox or to your account: secure your email account, then choose
        &quot;Forgot password&quot; on the sign-in page to set a new password, and tell the
        administrator of this service.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const PASSWORD_CHANGED_SUBJECT = 'Your password was changed';
