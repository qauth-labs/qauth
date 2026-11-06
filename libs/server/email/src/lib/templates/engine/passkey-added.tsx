import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, Paragraph } from './layout';

/**
 * The "passkey added" notice (#651; ADR-017 Decision 8, ACC-13's
 * `credential_added`): a passkey was bound to the account at a sign-in. It
 * carries no link and no secret, and a realm cannot switch it off. A passkey
 * is bound only after the password and a code mailed to this address, or
 * after the password within minutes of a sign-in that proved the address
 * before, so the notice says what a person who did not add it does.
 */

export interface PasskeyAddedEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
}

/** "A passkey was added to your account". */
export function PasskeyAddedEmail({ brand, baseUrl }: PasskeyAddedEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="A passkey was added to your account"
      title="A passkey was added"
    >
      <Paragraph brand={brand}>
        A passkey was just added to the account that uses this email address. From now on, signing
        in to the account takes the passkey, and the password alone no longer does.
      </Paragraph>
      <Paragraph brand={brand}>
        If this was not you, someone knows your password and can read the mail sent to this address:
        secure your email account, and tell the administrator of this service at once, who can
        remove the passkey.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const PASSKEY_ADDED_SUBJECT = 'A passkey was added to your account';
