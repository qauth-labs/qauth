import * as React from 'react';

import { DEFAULT_MAIL_BRAND } from '../engine-mail/brand';
import { MailFrame, Paragraph } from './engine/layout';

/**
 * React Email template sent when someone registers an address that already
 * has an account.
 *
 * Registration answers every address the same way, so the person who already
 * owns the address learns about the attempt here, and only here. The mail
 * carries no link and no token: nothing in it can sign anyone in or change the
 * account, so it is safe to send whoever made the attempt.
 *
 * @returns React component
 */
export function AccountExistsEmail() {
  return (
    <MailFrame
      brand={DEFAULT_MAIL_BRAND}
      preview="Someone tried to create an account with your email address"
      title="You already have an account"
    >
      <Paragraph brand={DEFAULT_MAIL_BRAND}>
        Someone just tried to create a QAuth account with this email address. You already have an
        account with it, so no new account was created and your existing account was not changed.
      </Paragraph>
      <Paragraph brand={DEFAULT_MAIL_BRAND}>
        If this was you, sign in with your existing password instead of registering again. If you no
        longer know your password, contact the administrator of this service.
      </Paragraph>
      <Paragraph brand={DEFAULT_MAIL_BRAND}>
        If this was not you, you can safely ignore this email. Nobody can sign in to your account
        without your password.
      </Paragraph>
    </MailFrame>
  );
}
