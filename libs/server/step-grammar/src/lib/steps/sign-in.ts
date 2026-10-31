import { passwordSchema } from '@qauth-labs/shared-validation';
import { z } from 'zod';

import { defineStep } from '../grammar';
import {
  base64url,
  constant,
  EMPTY_OBJECT,
  host,
  integer,
  integerEnum,
  matching,
  object,
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
 * `recovery_code` and `select_account` only by the Interaction API.
 */

export const identifier = defineStep({
  name: 'identifier',
  transports: ['interaction', 'fipa'],
  params: EMPTY_OBJECT,
  personal: EMPTY_OBJECT,
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
