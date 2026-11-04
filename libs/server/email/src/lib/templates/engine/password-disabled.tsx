import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, LinkButton, Paragraph } from './layout';

export interface PasswordDisabledEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
  /** The pass link, on the realm's auth server. */
  readonly passUrl: string;
  /** How long the pass stays valid, as prose. */
  readonly expiresIn: string;
}

/**
 * "Your password was disabled after too many attempts" (PRO-14, #637;
 * ADR-017 Decision 7, NIST SP 800-63B-4 §3.2.2): the failure ladder's hard
 * action turned the password off. The mail carries the pass that takes the
 * owner's reset past every per-address send tier, so a third party who
 * spends those tiers cannot keep the owner from the reset that ends the
 * disable. A realm cannot switch it off.
 */
export function PasswordDisabledEmail({
  brand,
  baseUrl,
  passUrl,
  expiresIn,
}: PasswordDisabledEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="Your password was turned off after too many wrong attempts"
      title="Your password was disabled"
    >
      <Paragraph brand={brand}>
        A wrong password was entered for the account that uses this email address too many times in
        a row, so its password was turned off to protect the account. It stays off until a new
        password is set.
      </Paragraph>
      <Paragraph brand={brand}>Use this link to set a new password:</Paragraph>
      <LinkButton brand={brand} href={passUrl} label="Set a new password" />
      <Paragraph brand={brand}>
        The link works once and expires in {expiresIn}. You will still be asked for a code that is
        mailed to this address, so the link is of no use to anyone without your mailbox.
      </Paragraph>
      <Paragraph brand={brand}>
        If you did not make these attempts, someone may be trying to guess your password. Choose a
        new password that you use nowhere else.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const PASSWORD_DISABLED_SUBJECT = 'Your password was disabled';
