import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { CodeBlock, EngineMailLayout, Paragraph } from './layout';

export interface EngineAccountExistsEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
  /**
   * The registration's code, when the registration goes on to help the owner
   * sign in (ADR-017 Decision 8): a new and an existing address both get a
   * code, so the page after the start looks the same for both.
   */
  readonly code?: string;
  /** How long the code stays valid, as prose. */
  readonly expiresIn?: string;
}

/**
 * "An account already exists" (PRO-14, #637; ADR-017 Decision 8): someone
 * started a registration with the address of an existing account. No account
 * was created and nothing changed. With a code, the person who started it can
 * go on to sign in to the existing account; without one, it is a notice only.
 */
export function EngineAccountExistsEmail({
  brand,
  baseUrl,
  code,
  expiresIn,
}: EngineAccountExistsEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="Someone tried to create an account with your email address"
      title="You already have an account"
    >
      <Paragraph brand={brand}>
        Someone just tried to create an account with this email address. You already have one, so no
        new account was created and your account was not changed.
      </Paragraph>
      {code === undefined ? (
        <Paragraph brand={brand}>
          If this was you, sign in to your existing account instead.
        </Paragraph>
      ) : (
        <>
          <Paragraph brand={brand}>
            If this was you, enter this code to continue. You will then sign in to your existing
            account:
          </Paragraph>
          <CodeBlock brand={brand} code={code} />
          <Paragraph brand={brand}>
            The code works once{expiresIn === undefined ? '' : ` and expires in ${expiresIn}`}.
          </Paragraph>
        </>
      )}
      <Paragraph brand={brand}>
        If this was not you, you can safely ignore this email. Nobody can sign in to your account
        with it.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const ENGINE_ACCOUNT_EXISTS_SUBJECT = 'You already have an account';
