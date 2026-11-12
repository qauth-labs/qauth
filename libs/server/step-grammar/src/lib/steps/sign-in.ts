import { passwordSchema } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { defineStep } from '../grammar';
import {
  array,
  base64url,
  closedEnum,
  constant,
  displayText,
  EMPTY_OBJECT,
  host,
  integer,
  integerEnum,
  matching,
  object,
  URI_CHARACTERS,
  uriMatching,
} from '../zod-kit';
import {
  accountIdentifier,
  identifierPersonal,
  LOGIN_HINT_DESCRIPTION,
  loginHint,
  sixDigitOtp,
  webauthnResponse,
} from './shared';

/**
 * The sign-in steps: who is signing in, and the factors that prove it.
 * `identifier`, `password`, `captcha`, `webauthn_get` and `totp` are the
 * steps of ADR-017 Decision 3 and may be served by both transports;
 * `recovery_code`, `select_account`, `upstream`, `upstream_link` and the two
 * path markers between a sign-in and a registration, `register` and
 * `sign_in` (#1079), only by the Interaction API.
 */

/** The identifier step's personal data: the request's `login_hint` as a prefill (#628). */
const identifierPrefill = object(
  {
    login_hint: displayText(
      'declared',
      254,
      "The authorization request's `login_hint` (OpenID Connect Core 1.0 §3.1.2.1), for the screen to pre-fill the identifier field with (#628). The client chose it, so it is only a suggestion: the person answers the step with it or with another identifier, and the server checks that answer as it checks any other. Absent when the request carried none or one that is no display value, and after an account switch."
    ).optional(),
  },
  'What the screen pre-fills the identifier field with.'
);

export const identifier = defineStep({
  name: 'identifier',
  transports: ['interaction', 'fipa'],
  params: EMPTY_OBJECT,
  personal: identifierPrefill,
  answer: object({ login_hint: loginHint }),
  errors: [],
  amr: [],
});

export const password = defineStep({
  name: 'password',
  transports: ['interaction', 'fipa'],
  params: EMPTY_OBJECT,
  personal: identifierPersonal,
  answer: object({
    // `passwordSchema` counts UTF-16 code units, as ADR-017 Decision 8 says;
    // Zod's own `.max()` counts code points.
    password: passwordSchema.min(1).meta({
      description:
        'The password. The server refuses one longer than 256 UTF-16 code units before anything else (ADR-017 Decision 8).',
    }),
    login_hint: loginHint
      .meta({
        description: `${LOGIN_HINT_DESCRIPTION} Sent only when the transaction holds no identifier yet: a page that asks for both at once.`,
      })
      .optional(),
  }),
  errors: ['invalid_credentials'],
  amr: ['pwd'],
});

export const captcha = defineStep({
  name: 'captcha',
  transports: ['interaction', 'fipa'],
  params: z
    .xor([
      object({
        provider: constant('pow', 'The built-in proof of work.'),
        challenge: base64url(22, 128, 'The puzzle the engine issued.'),
        difficulty: integer(1, 32, 'How many leading zero bits the answer must produce.'),
      }),
      object({
        provider: constant('hosted', 'A hosted provider the operator named.'),
        name: matching(z.string().min(1).max(32), '^[a-z][a-z0-9_-]{0,31}$').meta({
          description: 'The name the operator gave the hosted provider.',
        }),
        site_key: matching(z.string().min(1).max(256), '^[A-Za-z0-9._-]+$').meta({
          description: 'The provider’s public site key.',
        }),
      }),
    ])
    .meta({
      description: 'The challenge to solve: the built-in proof of work, or a hosted provider.',
    }),
  personal: EMPTY_OBJECT,
  answer: object({
    captcha_token: matching(z.string().min(1).max(4096), '^[!-~]+$').meta({
      description:
        'The solution, or the provider’s token: printable ASCII, so 4096 characters are 4096 bytes.',
    }),
  }),
  errors: ['captcha_failed'],
  amr: [],
});

export const webauthnGet = defineStep({
  name: 'webauthn_get',
  transports: ['interaction', 'fipa'],
  params: object({
    challenge: base64url(43, 128, 'The challenge, at least 32 random bytes.'),
    rpId: host('The relying party ID: the realm’s host.'),
    timeout: integer(1000, 600000, 'How long the ceremony may take, in milliseconds.').optional(),
    userVerification: constant(
      'required',
      'The server refuses an assertion without user verification.'
    ),
  }),
  personal: identifierPersonal,
  answer: object({ webauthn_response: webauthnResponse(8192, 'assertion') }),
  errors: ['invalid_credentials'],
  amr: ['pop', 'mfa'],
});

export const totp = defineStep({
  name: 'totp',
  transports: ['interaction', 'fipa'],
  params: object({ digits: integerEnum([6], 'How many digits the code has.') }),
  personal: identifierPersonal,
  answer: object({ otp: sixDigitOtp }),
  errors: ['invalid_credentials'],
  amr: ['otp'],
});

export const recoveryCode = defineStep({
  name: 'recovery_code',
  transports: ['interaction'],
  params: EMPTY_OBJECT,
  personal: identifierPersonal,
  answer: object({
    recovery_code: matching(z.string().min(16).max(39), '^[A-Za-z0-9 -]+$').meta({
      description:
        'The code as the person typed it. The server ignores case, spaces and dashes before comparing.',
    }),
  }),
  errors: ['invalid_credentials'],
  amr: [],
});

export const selectAccount = defineStep({
  name: 'select_account',
  transports: ['interaction'],
  params: EMPTY_OBJECT,
  personal: object({
    accounts: z
      .array(
        object({
          account: base64url(
            22,
            64,
            'An opaque reference to the account’s session, valid for this interaction only.'
          ),
          identifier: accountIdentifier,
          current: z
            .boolean()
            .meta({ description: 'Whether this is the account the browser last used.' }),
        })
      )
      .min(1)
      .max(16)
      .meta({
        description: 'The accounts the browser holds a session for, the current one first.',
      }),
  }),
  answer: object({
    account: base64url(22, 64, 'The `account` reference of the chosen entry.'),
  }),
  errors: ['account_unavailable'],
  amr: [],
});

/** The pattern of an upstream provider's name: the AuthMethod `type` (`oidc_corp`). */
const UPSTREAM_PROVIDER_PATTERN = '^[a-z][a-z0-9_]{0,62}$';

/** An upstream provider's name, as the list carries it and the answer names it. */
function upstreamProvider(description: string) {
  return matching(z.string().min(1).max(63), UPSTREAM_PROVIDER_PATTERN).meta({ description });
}

export const upstream = defineStep({
  name: 'upstream',
  transports: ['interaction'],
  params: object({
    providers: array(
      object({
        provider: upstreamProvider('The provider’s name, which the answer names.'),
        name: displayText(
          'realm',
          64,
          'The provider’s name as the operator set it, for its button.'
        ),
        icon: uriMatching(
          2048,
          `^https://${URI_CHARACTERS}+$`,
          'An absolute `https` URL on the realm origin of a PNG icon for the button. Nothing supplies one yet (#714).'
        ).optional(),
      }),
      1,
      16,
      'The realm’s upstream identity providers, in the order the screen shows them.'
    ),
  }),
  personal: EMPTY_OBJECT,
  answer: object({ provider: upstreamProvider('The `provider` of the entry the person picked.') }),
  errors: ['provider_unavailable'],
  amr: [],
});

export const upstreamLink = defineStep({
  name: 'upstream_link',
  transports: ['interaction'],
  params: object({
    provider: object({
      provider: upstreamProvider('The provider’s name: the AuthMethod `type`.'),
      name: displayText(
        'realm',
        64,
        'The provider’s name as the operator set it, for the screen’s text.'
      ),
    }),
    create: z.boolean().meta({
      description:
        'Whether the person may start a new account with the identity: the realm allows sign-up, the new account can be verified (the provider vouches for its address, or gave one an emailed code verifies), and the provider’s claims fit what the interaction keeps. `false` offers the existing account only.',
    }),
  }),
  personal: EMPTY_OBJECT,
  answer: object({
    decision: closedEnum(
      ['create', 'link'],
      'A new account with the identity, or the existing account the person signs in to next.'
    ),
  }),
  errors: [],
  amr: [],
});

/** A path marker (#1079): turns a sign-in at its first step into a registration. */
export const register = defineStep({
  name: 'register',
  transports: ['interaction'],
  params: EMPTY_OBJECT,
  personal: EMPTY_OBJECT,
  answer: EMPTY_OBJECT,
  errors: [],
  amr: [],
});

/** A path marker (#1079): turns a registration at its address step back into a sign-in. */
export const signIn = defineStep({
  name: 'sign_in',
  transports: ['interaction'],
  params: EMPTY_OBJECT,
  personal: EMPTY_OBJECT,
  answer: EMPTY_OBJECT,
  errors: [],
  amr: [],
});
