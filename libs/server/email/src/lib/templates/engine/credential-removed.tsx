import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, Paragraph } from './layout';

/**
 * The removal notices (#844; ADR-020 §3 "Emails"): a passkey was removed from
 * the account, or its authenticator app was, on the hosted account page. They
 * carry no link and no secret, and a realm cannot switch them off: they are
 * about a credential. A removal needs a sign-in from the last five minutes
 * with the account's strongest factor, or with a recovery code in place of a
 * lost one, so each says what a person who did not do it does.
 */

export interface CredentialRemovedEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
}

/** What to do for a person who did not act: someone signed in to the account. */
function NotYou({ brand }: { readonly brand: MailBrand }) {
  return (
    <Paragraph brand={brand}>
      If this was not you, someone was able to sign in to your account: tell the administrator of
      this service at once, and if you use a password, choose &quot;Forgot password&quot; on the
      sign-in page to set a new one.
    </Paragraph>
  );
}

/** "A passkey was removed from your account". */
export function PasskeyRemovedEmail({ brand, baseUrl }: CredentialRemovedEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="A passkey was removed from your account"
      title="A passkey was removed"
    >
      <Paragraph brand={brand}>
        A passkey was just removed from the account that uses this email address, on its account
        page. That passkey no longer signs in to the account.
      </Paragraph>
      <NotYou brand={brand} />
    </EngineMailLayout>
  );
}

export const PASSKEY_REMOVED_SUBJECT = 'A passkey was removed from your account';

/** "The authenticator app was removed from your account". */
export function TotpRemovedEmail({ brand, baseUrl }: CredentialRemovedEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="The authenticator app was removed from your account"
      title="The authenticator app was removed"
    >
      <Paragraph brand={brand}>
        The authenticator app was just removed from the account that uses this email address, on its
        account page. Signing in to the account no longer asks for a code from it.
      </Paragraph>
      <NotYou brand={brand} />
    </EngineMailLayout>
  );
}

export const TOTP_REMOVED_SUBJECT = 'The authenticator app was removed from your account';
