import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, Paragraph } from './layout';

/**
 * The recovery codes' notices (#649; ADR-017 Decisions 7 and 8): a code
 * used, a set replaced, and 100 wrong codes in a row. None carries a link or
 * a secret; a realm switches none of them off. A recovery code is asked for
 * only after the password, so each notice says what a person who did not act
 * does: set a new password through "Forgot password", which also needs the
 * second factor the account holds, and tell the administrator.
 */

interface RecoveryNoticeProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
}

/** What to do for a person who did not act: the same in every notice. */
function NotYou({ brand }: { readonly brand: MailBrand }) {
  return (
    <Paragraph brand={brand}>
      If this was not you, someone knows your password: choose &quot;Forgot password&quot; on the
      sign-in page to set a new one, and tell the administrator of this service.
    </Paragraph>
  );
}

export interface RecoveryCodeUsedEmailProps extends RecoveryNoticeProps {
  /** How many codes of the set are left unused, 0 to 10. */
  readonly unusedCodes: number;
}

/** "A recovery code was used": a code stood in for the second factor at a sign-in. */
export function RecoveryCodeUsedEmail({ brand, baseUrl, unusedCodes }: RecoveryCodeUsedEmailProps) {
  const left =
    unusedCodes === 0
      ? 'It was the last unused code of your set: create a new set before you need one.'
      : `Each code works once: ${unusedCodes} of your codes ${unusedCodes === 1 ? 'is' : 'are'} left.`;
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="A recovery code was used to sign in to your account"
      title="A recovery code was used"
    >
      <Paragraph brand={brand}>
        A recovery code was just used in place of the second factor to sign in to the account that
        uses this email address. {left}
      </Paragraph>
      <NotYou brand={brand} />
    </EngineMailLayout>
  );
}

export const RECOVERY_CODE_USED_SUBJECT = 'A recovery code was used to sign in';

/** "Recovery codes were regenerated": a new set replaced the old one. */
export function RecoveryCodesRegeneratedEmail({ brand, baseUrl }: RecoveryNoticeProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="Your account has a new set of recovery codes"
      title="Your recovery codes were replaced"
    >
      <Paragraph brand={brand}>
        A new set of recovery codes was just created for the account that uses this email address,
        and every code of the old set stopped working. Keep the new codes somewhere safe, apart from
        your devices.
      </Paragraph>
      <NotYou brand={brand} />
    </EngineMailLayout>
  );
}

export const RECOVERY_CODES_REGENERATED_SUBJECT = 'Your recovery codes were replaced';

/** "Recovery codes failed 100 times": wrong codes, 100 in a row (ADR-017 Decision 7). */
export function RecoveryCodesFailedEmail({ brand, baseUrl }: RecoveryNoticeProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="Wrong recovery codes were tried on your account"
      title="Wrong recovery codes were tried"
    >
      <Paragraph brand={brand}>
        Wrong recovery codes were entered 100 times in a row to sign in to the account that uses
        this email address, each after the right password. Every further try now waits up to 15
        minutes.
      </Paragraph>
      <NotYou brand={brand} />
    </EngineMailLayout>
  );
}

export const RECOVERY_CODES_FAILED_SUBJECT = 'Wrong recovery codes were tried on your account';
