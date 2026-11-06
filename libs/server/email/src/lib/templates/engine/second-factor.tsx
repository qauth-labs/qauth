import * as React from 'react';

import type { MailBrand } from '../../engine-mail/brand';
import { EngineMailLayout, Paragraph } from './layout';

/**
 * The TOTP's notices (#653; ADR-017 Decisions 7 and 8, ADR-020 §3
 * "Emails"): an authenticator app added, the authenticator app turned off
 * after 100 wrong codes in a row, and a wrong code after a correct password.
 * None carries a link or a secret, and a realm switches none of them off:
 * the first two are about a credential, and ADR-017 Decision 7 names the
 * third. Each says what a person who did not act does: tell the
 * administrator, and set a new password. The wrong-code notice is sent only
 * after a correct password; the turned-off one may follow another first
 * factor (an upstream sign-in), so it names none.
 */

interface SecondFactorNoticeProps {
  readonly brand: MailBrand;
  readonly baseUrl: string;
}

/** What to do for a person who did not act: someone knows the password. */
function NotYou({ brand }: { readonly brand: MailBrand }) {
  return (
    <Paragraph brand={brand}>
      If this was not you, someone knows your password: choose &quot;Forgot password&quot; on the
      sign-in page to set a new one, and tell the administrator of this service.
    </Paragraph>
  );
}

/** "An authenticator app was added": a TOTP was bound to the account at a sign-in. */
export function TotpAddedEmail({ brand, baseUrl }: SecondFactorNoticeProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="An authenticator app was added to your account"
      title="An authenticator app was added"
    >
      <Paragraph brand={brand}>
        An authenticator app was just set up for the account that uses this email address. From now
        on, signing in to the account takes a code from that app after the password.
      </Paragraph>
      <Paragraph brand={brand}>
        If this was not you, someone knows your password and was able to sign in: tell the
        administrator of this service at once, who can remove the authenticator app.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const TOTP_ADDED_SUBJECT = 'An authenticator app was added to your account';

/** "Your authenticator app was turned off": 100 wrong codes in a row (ADR-017 Decision 7). */
export function SecondFactorDisabledEmail({ brand, baseUrl }: SecondFactorNoticeProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="Your authenticator app was turned off"
      title="Your authenticator app was turned off"
    >
      <Paragraph brand={brand}>
        Wrong codes from an authenticator app were entered 100 times in a row for the account that
        uses this email address, each after a correct first sign-in step, so the app no longer signs
        in to it. To sign in, enter one of your recovery codes in its place: the sign-in then asks
        you to set up the app again.
      </Paragraph>
      <Paragraph brand={brand}>
        If this was not you, someone got past the first step of signing in to your account, with
        your password or another way you sign in: tell the administrator of this service, and if you
        use a password, choose &quot;Forgot password&quot; on the sign-in page to set a new one.
      </Paragraph>
    </EngineMailLayout>
  );
}

export const SECOND_FACTOR_DISABLED_SUBJECT = 'Your authenticator app was turned off';

/** "A wrong code was entered after your password": at most once a day. */
export function SecondFactorFailedEmail({ brand, baseUrl }: SecondFactorNoticeProps) {
  return (
    <EngineMailLayout
      brand={brand}
      baseUrl={baseUrl}
      preview="A wrong code was entered after your password"
      title="A wrong code was entered after your password"
    >
      <Paragraph brand={brand}>
        Someone signing in to the account that uses this email address entered its password and then
        a wrong code from the authenticator app. A mistyped code does this too. This notice is sent
        at most once a day.
      </Paragraph>
      <NotYou brand={brand} />
    </EngineMailLayout>
  );
}

export const SECOND_FACTOR_FAILED_SUBJECT = 'A wrong code was entered after your password';
