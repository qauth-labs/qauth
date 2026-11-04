import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, LinkButton, Paragraph } from './layout';

/** What the pass starts: a reset of the account, or the registration of the address. */
export type MailPassFlow = 'reset' | 'register';

export interface SendCeilingEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
  readonly flow: MailPassFlow;
  /** The pass link, on the realm's auth server. */
  readonly passUrl: string;
  /** How long the pass stays valid, as prose. */
  readonly expiresIn: string;
}

/**
 * The send-ceiling notice (PRO-14, #637; ADR-017 Decision 5): codes were
 * requested for this address past the per-address send ceiling, so every
 * further request is refused for a while, whoever makes it. The notice
 * carries the pass that takes one reset or registration start of the owner
 * past every per-address tier, so a third party who spends the ceiling cannot
 * keep the owner out. A realm cannot switch it off.
 */
export function SendCeilingEmail({
  brand,
  baseUrl,
  flow,
  passUrl,
  expiresIn,
}: SendCeilingEmailProps) {
  const what =
    flow === 'reset'
      ? 'to recover the account that uses this email address'
      : 'to create an account with this email address';
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="Codes for your email address were requested many times"
      title="Codes were requested many times"
    >
      <Paragraph brand={brand}>
        Codes {what} were requested many times in the last 24 hours, so no more are sent for now.
      </Paragraph>
      <Paragraph brand={brand}>
        If you asked for them and still need one, use this link to continue:
      </Paragraph>
      <LinkButton
        brand={brand}
        href={passUrl}
        label={flow === 'reset' ? 'Recover my account' : 'Create my account'}
      />
      <Paragraph brand={brand}>
        The link works once and expires in {expiresIn}. You will still be asked for a code that is
        mailed to this address, so the link is of no use to anyone without your mailbox.
      </Paragraph>
      <Paragraph brand={brand}>
        If you did not ask for them, someone else is using your address. You can safely ignore this
        email: nothing about your account has changed.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const SEND_CEILING_SUBJECT = 'Codes were requested for your email address';
