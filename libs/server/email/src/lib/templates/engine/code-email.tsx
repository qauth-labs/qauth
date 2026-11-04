import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { CodeBlock, EngineMailLayout, Paragraph } from './layout';

/** Why a code was mailed: the purposes of the `email_code` step (ADR-017 Decisions 3 and 5). */
export type MailCodePurpose = 'verify_account' | 'recovery' | 'confirm_sign_in';

export interface CodeEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
  readonly purpose: MailCodePurpose;
  /** The code: 6 or 8 digits. */
  readonly code: string;
  /** How long the code stays valid, as prose ("10 minutes"). */
  readonly expiresIn: string;
}

/** The heading, preview and explanation of each purpose. */
const COPY: Readonly<
  Record<MailCodePurpose, { title: string; preview: string; why: string; notYou: string }>
> = {
  verify_account: {
    title: 'Your verification code',
    preview: 'Your code to verify this email address',
    why: 'Enter this code to prove that this email address is yours:',
    notYou:
      'If you did not ask for this code, you can safely ignore this email. Nothing happens without it.',
  },
  recovery: {
    title: 'Your account recovery code',
    preview: 'Your code to recover your account',
    why: 'Someone asked to recover the account that uses this email address, for example to set a new password. Enter this code to continue:',
    notYou:
      'If you did not ask for this code, you can safely ignore this email. Your password has not been changed, and nobody can change it without this code.',
  },
  confirm_sign_in: {
    title: 'Confirm your sign-in',
    preview: 'Your code to finish signing in',
    why: 'Someone just entered the correct password of your account. Enter this code to finish signing in:',
    notYou:
      'If you are not signing in right now, someone else knows your password. Do not share this code, and set a new password.',
  },
};

/**
 * A mailed code (PRO-14, #637; ADR-017 Decision 5): it proves control of the
 * mailbox, to verify an account, to recover one or to confirm a sign-in after
 * the password. It is never a sign-in factor on its own. No link: the code is
 * typed into the page that asked for it.
 */
export function CodeEmail({ brand, baseUrl, purpose, code, expiresIn }: CodeEmailProps) {
  const copy = COPY[purpose];
  return (
    <EngineMailLayout brand={brand} baseUrl={baseUrl} preview={copy.preview} title={copy.title}>
      <Paragraph brand={brand}>{copy.why}</Paragraph>
      <CodeBlock brand={brand} code={code} />
      <Paragraph brand={brand}>
        The code works once and expires in {expiresIn}. Enter it only on the page where you asked
        for it.
      </Paragraph>
      <Paragraph brand={brand}>{copy.notYou}</Paragraph>
    </EngineMailLayout>
  );
}

/** The subject line of a code mail, by purpose. */
export function codeEmailSubject(purpose: MailCodePurpose): string {
  return COPY[purpose].title;
}
