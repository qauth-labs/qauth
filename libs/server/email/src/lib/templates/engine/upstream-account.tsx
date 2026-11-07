import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, Paragraph } from './layout';

/**
 * The upstream account notices (#670; ADR-020 §3, NIST SP 800-63C-4 §5.4):
 * an upstream identity provider's account was linked to the account, or
 * removed from it. They carry no link and no secret, and a realm cannot
 * switch them off. A link needs a sign-in to the account with its own
 * factors right after the provider proved the identity, and an unlink a
 * fresh sign-in, so each says what a person who did not do it does.
 *
 * The provider's name is the operator's display name, shown as text.
 */

export interface UpstreamAccountEmailProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
  /** The provider's name as the operator set it. */
  readonly providerName: string;
}

/** "An account was linked to your account". */
export function UpstreamLinkedEmail({ brand, baseUrl, providerName }: UpstreamAccountEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview={`Your ${providerName} account was linked`}
      title="An account was linked"
    >
      <Paragraph brand={brand}>
        An account at {providerName} was just linked to the account that uses this email address.
        From now on, signing in with that {providerName} account also signs in to this account.
      </Paragraph>
      <Paragraph brand={brand}>
        If this was not you, someone signed in to your account: change your password, and tell the
        administrator of this service at once, who can remove the linked account.
      </Paragraph>
    </EngineMailLayout>
  );
}

/** "An account was unlinked from your account". */
export function UpstreamUnlinkedEmail({ brand, baseUrl, providerName }: UpstreamAccountEmailProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview={`Your ${providerName} account was unlinked`}
      title="An account was unlinked"
    >
      <Paragraph brand={brand}>
        The {providerName} account linked to the account that uses this email address was just
        removed. Signing in with it no longer signs in to this account.
      </Paragraph>
      <Paragraph brand={brand}>
        If this was not you, someone signed in to your account: change your password, and tell the
        administrator of this service at once.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const UPSTREAM_LINKED_SUBJECT = 'An account was linked to your account';
export const UPSTREAM_UNLINKED_SUBJECT = 'An account was unlinked from your account';
