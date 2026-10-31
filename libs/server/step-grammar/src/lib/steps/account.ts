import { z } from 'zod';

import { defineStep } from '../grammar';
import {
  array,
  base64url,
  closedEnum,
  constant,
  displayText,
  distinctArray,
  EMPTY_OBJECT,
  host,
  integer,
  integerEnum,
  matching,
  object,
  URI_CHARACTERS,
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
 * The steps that create, verify or recover an account and bind its
 * authenticators. `email_code`, `new_password`, `password_reset` and
 * `webauthn_create` are steps of ADR-017 Decision 3 and may be served by both
 * transports; `totp_setup` and `recovery_codes` only by the Interaction API.
 */

/** Why an email code was sent. `confirm_sign_in` is the FiPA endpoint's alone (`interaction-mapper.ts`). */
export const EMAIL_CODE_PURPOSES = ['verify_account', 'recovery', 'confirm_sign_in'] as const;

export const emailCode = defineStep({
  name: 'email_code',
  transports: ['interaction', 'fipa'],
  params: object({
    purpose: closedEnum(
      EMAIL_CODE_PURPOSES,
      'Why the code was sent, so one screen can say so: to verify the account, to recover the account, or (FiPA endpoint only; the Interaction API never offers it) to confirm a sign-in after the password.'
    ),
    length: integerEnum(
      [6, 8],
      'How many digits the code has: six after a password, eight for recovery and registration.'
    ),
    expires_in: integer(1, 86400, 'How many seconds the code stays valid.'),
    resend_after: integer(0, 3600, 'How many seconds until another code may be asked for.'),
  }),
  personal: object(
    { identifier: accountIdentifier.optional() },
    'The address the code went to, when the transaction holds one.'
  ),
  answer: object({
    otp: matching(z.string(), '^(?:[0-9]{6}|[0-9]{8})$')
      .meta({ description: 'The code. Leave it out to ask for a new one.' })
      .optional(),
  }),
  errors: ['invalid_credentials', 'code_expired'],
  amr: [],
});

export const newPassword = defineStep({
  name: 'new_password',
  transports: ['interaction', 'fipa'],
  params: object({
    purpose: closedEnum(
      ['register', 'reset', 'update_required'],
      'Why a new password is asked for, so one screen can say so: a new account, a reset, or a required update.'
    ),
    min_length: integer(8, 256, 'The shortest password the policy accepts, in code points.'),
    max_length: integer(8, 256, 'The longest password the policy accepts.'),
    reasons: distinctArray(
      closedEnum(['too_short', 'too_long', 'blocklisted', 'too_weak'], 'One reason.'),
      1,
      4,
      'After a refused answer: why the policy refused it.'
    ).optional(),
  }),
  personal: identifierPersonal,
  answer: object({
    new_password: z.string().min(1).max(256).meta({ description: 'The new password.' }),
  }),
  errors: ['password_rejected'],
  amr: [],
});

export const passwordReset = defineStep({
  name: 'password_reset',
  transports: ['interaction', 'fipa'],
  params: EMPTY_OBJECT,
  personal: EMPTY_OBJECT,
  answer: object({
    login_hint: loginHint
      .meta({
        description: `${LOGIN_HINT_DESCRIPTION} Sent only when the transaction holds no identifier yet.`,
      })
      .optional(),
  }),
  errors: [],
  amr: [],
});

export const webauthnCreate = defineStep({
  name: 'webauthn_create',
  transports: ['interaction', 'fipa'],
  params: object({
    optional: z.boolean().meta({
      description:
        'Whether this is an offer the person may decline: an answer with no `webauthn_response` declines it.',
    }),
    options: object({
      challenge: base64url(43, 128, 'The challenge, at least 32 random bytes.'),
      rp: object({
        id: host('The relying party ID: the realm’s host.'),
        name: displayText('realm', 64, 'The realm’s display name.'),
      }),
      pubKeyCredParams: array(
        object({
          type: constant('public-key'),
          alg: integerEnum([-8, -7, -257], 'EdDSA, ES256 or RS256.'),
        }),
        1,
        8,
        'The COSE algorithms the server accepts, preferred first.'
      ),
      timeout: integer(1000, 600000, 'How long the ceremony may take, in milliseconds.').optional(),
      authenticatorSelection: object({
        residentKey: constant('required', 'A passkey is discoverable.'),
        userVerification: constant('required'),
      }),
      attestation: constant(
        'none',
        'QAuth asks for no attestation and claims nothing about the key store.'
      ),
    }),
  }),
  personal: object({
    identifier: accountIdentifier.optional(),
    user: object({
      id: base64url(1, 86, 'The user handle: an opaque id, at most 64 bytes.'),
      name: displayText('account', 64, 'The account name the authenticator shows.'),
      displayName: displayText('account', 64, 'The display name the authenticator shows.'),
    }),
    excludeCredentials: array(
      object({
        type: constant('public-key'),
        id: base64url(1, 1366, 'The credential id.'),
        transports: z
          .array(
            closedEnum(
              ['ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'],
              'How the authenticator is reached.'
            )
          )
          .max(6)
          .optional(),
      }),
      0,
      32,
      'The account’s passkeys, so the authenticator does not make a second one.'
    ),
  }),
  answer: object({ webauthn_response: webauthnResponse(16384, 'attestation').optional() }),
  errors: ['invalid_credentials'],
  amr: [],
});

export const totpSetup = defineStep({
  name: 'totp_setup',
  transports: ['interaction'],
  params: object({
    algorithm: closedEnum(['SHA1'], 'The HMAC algorithm.'),
    digits: integerEnum([6], 'How many digits a code has.'),
    period: integerEnum([30], 'How many seconds a code lasts.'),
  }),
  personal: object({
    identifier: accountIdentifier.optional(),
    secret: matching(z.string().min(32).max(32), '^[A-Z2-7]{32}$').meta({
      description: 'The shared secret, 160 bits in base32 (RFC 4648 §6), unpadded.',
    }),
    otpauth_uri: matching(z.string().max(1024), `^otpauth://totp/${URI_CHARACTERS}+$`).meta({
      format: 'uri',
      description: 'The same secret as an `otpauth://` URI, for the QR code.',
    }),
  }),
  answer: object({ otp: sixDigitOtp }),
  errors: ['invalid_credentials'],
  amr: [],
});

/** One recovery code as the server shows it: 80 bits of base32, in four groups. */
const RECOVERY_CODE_PATTERN = '^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$';

export const recoveryCodes = defineStep({
  name: 'recovery_codes',
  transports: ['interaction'],
  params: object({ count: integerEnum([10], 'How many codes the set holds.') }),
  personal: object({
    codes: distinctArray(
      matching(z.string().min(19).max(19), RECOVERY_CODE_PATTERN).meta({
        description: 'One code.',
      }),
      10,
      10,
      'The codes, each usable once.'
    ),
  }),
  answer: object({
    acknowledged: constant(
      true,
      'The person confirms they saved the codes. In a form post: `true`.'
    ),
  }),
  errors: [],
  amr: [],
});
