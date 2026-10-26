import {
  base64url,
  closedEnum,
  closedObject,
  displayText,
  EMPTY_OBJECT,
  host,
  object,
} from '../schema-kit';
import { defineStep } from '../step-definition';
import {
  accountIdentifier,
  identifierPersonal,
  loginHint,
  sixDigitOtp,
  webauthnResponse,
} from './shared';
import { EXAMPLE_CHALLENGE, EXAMPLE_REDIRECT } from './sign-in';

/**
 * The steps that create, verify or recover an account and bind its
 * authenticators. `email_code`, `new_password`, `password_reset` and
 * `webauthn_create` are steps of ADR-017 Decision 3 and are served by both
 * transports; `totp_setup` and `recovery_codes` only by the Interaction API.
 */

export const emailCode = defineStep({
  name: 'email_code',
  transports: ['interaction', 'fipa'],
  summary: 'Asks for the code mailed to the account’s address.',
  description:
    'An emailed code proves control of a mailbox: it verifies a password account’s address and recovers an account. It is never a sign-in factor and adds no `amr` value (ADR-017 Decision 5). An answer with no `otp` asks for the code again. Works without JavaScript.',
  params: object(
    {
      purpose: closedEnum(
        ['verify_address', 'recovery', 'confirm_sign_in'],
        'Why the code was sent, so one screen can say so: to verify the address, to recover the account, or (FiPA endpoint only; the Interaction API never offers it) to confirm a sign-in after the password.'
      ),
      length: {
        type: 'integer',
        enum: [6, 8],
        description:
          'How many digits the code has: six after a password, eight for recovery and registration.',
      },
      expires_in: {
        type: 'integer',
        minimum: 1,
        maximum: 86400,
        description: 'How many seconds the code stays valid.',
      },
      resend_after: {
        type: 'integer',
        minimum: 0,
        maximum: 3600,
        description: 'How many seconds until another code may be asked for.',
      },
    },
    ['purpose', 'length', 'expires_in', 'resend_after']
  ),
  personal: object(
    { identifier: accountIdentifier },
    [],
    'The address the code went to, when the transaction holds one.'
  ),
  answer: closedObject(
    {
      otp: {
        type: 'string',
        pattern: '^(?:[0-9]{6}|[0-9]{8})$',
        description: 'The code. Leave it out to ask for a new one.',
      },
    },
    []
  ),
  errors: ['invalid_credentials', 'code_expired'],
  amr: [],
  example: {
    params: { purpose: 'verify_address', length: 6, expires_in: 600, resend_after: 60 },
    answer: { otp: '482913' },
    personal: { identifier: 'alice@example.com' },
    next: { redirect: EXAMPLE_REDIRECT },
  },
});

export const newPassword = defineStep({
  name: 'new_password',
  transports: ['interaction', 'fipa'],
  summary: 'Asks for a new password.',
  description:
    'Sets a password through the one password policy (ADR-017 Decision 8): at registration, at the end of a reset, or when an admin or a breach-list match requires a new one (ADR-020 §3). The reasons of a refusal are returned, never prose. The page marks the field for password managers, with the identifier from the personal data as the username. Works without JavaScript.',
  params: object(
    {
      purpose: closedEnum(
        ['register', 'reset', 'update_required'],
        'Why a new password is asked for, so one screen can say so: a new account, a reset, or a required update.'
      ),
      min_length: {
        type: 'integer',
        minimum: 8,
        maximum: 256,
        description: 'The shortest password the policy accepts, in code points.',
      },
      max_length: {
        type: 'integer',
        minimum: 8,
        maximum: 256,
        description: 'The longest password the policy accepts.',
      },
      reasons: {
        type: 'array',
        description: 'After a refused answer: why the policy refused it.',
        minItems: 1,
        maxItems: 4,
        uniqueItems: true,
        items: closedEnum(['too_short', 'too_long', 'blocklisted', 'too_weak'], 'One reason.'),
      },
    },
    ['purpose', 'min_length', 'max_length']
  ),
  personal: identifierPersonal,
  answer: closedObject(
    {
      new_password: {
        type: 'string',
        minLength: 1,
        maxLength: 256,
        description: 'The new password.',
      },
    },
    ['new_password']
  ),
  errors: ['password_rejected'],
  amr: [],
  example: {
    params: { purpose: 'reset', min_length: 15, max_length: 256, reasons: ['too_short'] },
    error: 'password_rejected',
    answer: { new_password: 'a much longer passphrase than before' },
    personal: { identifier: 'alice@example.com' },
    next: { redirect: EXAMPLE_REDIRECT },
  },
});

export const passwordReset = defineStep({
  name: 'password_reset',
  transports: ['interaction', 'fipa'],
  summary: 'Starts a password reset.',
  description:
    'A path marker: answering it starts a reset. The next step is `email_code` with `purpose` `recovery` for every address, known or not; mail goes only to a known address with a password. A reset never unlocks an account whose strongest authenticator is stronger than email (ADR-017 Decision 8).',
  params: EMPTY_OBJECT,
  personal: EMPTY_OBJECT,
  answer: closedObject(
    {
      login_hint: {
        ...loginHint,
        description: `${String(loginHint['description'])} Sent only when the transaction holds no identifier yet.`,
      },
    },
    []
  ),
  errors: [],
  amr: [],
  example: {
    params: {},
    answer: {},
    next: { step: 'email_code' },
  },
});

export const webauthnCreate = defineStep({
  name: 'webauthn_create',
  transports: ['interaction', 'fipa'],
  summary: 'Offers or asks to create a passkey.',
  description:
    'Passkey enrolment. `options` is the WebAuthn Level 3 creation options as JSON without `user` and `excludeCredentials`, which are the account’s own data and come with the personal data; the page joins the two for `PublicKeyCredential.parseCreationOptionsFromJSON()`. The RP ID is the realm’s host and locks at the first enrolment (ADR-019 Decision 2). Enrolment adds no `amr` value. Needs JavaScript.',
  params: object(
    {
      optional: {
        type: 'boolean',
        description:
          'Whether this is an offer the person may decline: an answer with no `webauthn_response` declines it.',
      },
      options: object(
        {
          challenge: base64url(43, 128, 'The challenge, at least 32 random bytes.'),
          rp: object(
            {
              id: host('The relying party ID: the realm’s host.'),
              name: displayText('realm', 64, 'The realm’s display name.'),
            },
            ['id', 'name']
          ),
          pubKeyCredParams: {
            type: 'array',
            minItems: 1,
            maxItems: 8,
            description: 'The COSE algorithms the server accepts, preferred first.',
            items: object(
              {
                type: { const: 'public-key' },
                alg: {
                  type: 'integer',
                  enum: [-8, -7, -257],
                  description: 'EdDSA, ES256 or RS256.',
                },
              },
              ['type', 'alg']
            ),
          },
          timeout: {
            type: 'integer',
            minimum: 1000,
            maximum: 600000,
            description: 'How long the ceremony may take, in milliseconds.',
          },
          authenticatorSelection: object(
            {
              residentKey: { const: 'required', description: 'A passkey is discoverable.' },
              userVerification: { const: 'required' },
            },
            ['residentKey', 'userVerification']
          ),
          attestation: {
            const: 'none',
            description: 'QAuth asks for no attestation and claims nothing about the key store.',
          },
        },
        ['challenge', 'rp', 'pubKeyCredParams', 'authenticatorSelection', 'attestation']
      ),
    },
    ['optional', 'options']
  ),
  personal: object(
    {
      identifier: accountIdentifier,
      user: object(
        {
          id: base64url(1, 86, 'The user handle: an opaque id, at most 64 bytes.'),
          name: displayText('account', 64, 'The account name the authenticator shows.'),
          displayName: displayText('account', 64, 'The display name the authenticator shows.'),
        },
        ['id', 'name', 'displayName']
      ),
      excludeCredentials: {
        type: 'array',
        description: 'The account’s passkeys, so the authenticator does not make a second one.',
        minItems: 0,
        maxItems: 32,
        items: object(
          {
            type: { const: 'public-key' },
            id: base64url(1, 1366, 'The credential id.'),
            transports: {
              type: 'array',
              maxItems: 6,
              items: closedEnum(
                ['ble', 'hybrid', 'internal', 'nfc', 'smart-card', 'usb'],
                'How the authenticator is reached.'
              ),
            },
          },
          ['type', 'id']
        ),
      },
    },
    ['user', 'excludeCredentials']
  ),
  answer: closedObject({ webauthn_response: webauthnResponse(16384, 'attestation') }, []),
  errors: ['invalid_credentials'],
  amr: [],
  example: {
    params: {
      optional: true,
      options: {
        challenge: EXAMPLE_CHALLENGE,
        rp: { id: 'auth.example.com', name: 'Example' },
        pubKeyCredParams: [
          { type: 'public-key', alg: -8 },
          { type: 'public-key', alg: -7 },
          { type: 'public-key', alg: -257 },
        ],
        timeout: 300000,
        authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
        attestation: 'none',
      },
    },
    answer: {
      webauthn_response: JSON.stringify({
        id: 'mC1lKXgSi0S3vW2mU1Nwhg',
        rawId: 'mC1lKXgSi0S3vW2mU1Nwhg',
        type: 'public-key',
        response: {
          clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0',
          attestationObject: 'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjE',
          transports: ['internal', 'hybrid'],
        },
        authenticatorAttachment: 'platform',
        clientExtensionResults: {},
      }),
    },
    personal: {
      identifier: 'alice@example.com',
      user: {
        id: 'b2Zmc2V0LXVzZXItaGFuZGxl',
        name: 'alice@example.com',
        displayName: 'alice@example.com',
      },
      excludeCredentials: [],
    },
    next: { step: 'recovery_codes' },
  },
});

export const totpSetup = defineStep({
  name: 'totp_setup',
  transports: ['interaction'],
  summary: 'Sets up an authenticator app.',
  description:
    'TOTP enrolment, with the fixed parameters of ADR-020 §3. The secret is personal data: readable with the flow cookie while this step is current, and never after. It is bound only after a first valid code (ADR-017 Decision 8). A password-only account’s first binding also needs a code mailed to its address in the same transaction, and an unclaimed account never reaches this step. Enrolment adds no `amr` value. The page shows the secret as a QR code and as text.',
  params: object(
    {
      algorithm: closedEnum(['SHA1'], 'The HMAC algorithm.'),
      digits: { type: 'integer', enum: [6], description: 'How many digits a code has.' },
      period: { type: 'integer', enum: [30], description: 'How many seconds a code lasts.' },
    },
    ['algorithm', 'digits', 'period']
  ),
  personal: object(
    {
      identifier: accountIdentifier,
      secret: {
        type: 'string',
        minLength: 32,
        maxLength: 32,
        pattern: '^[A-Z2-7]{32}$',
        description: 'The shared secret, 160 bits in base32 (RFC 4648 §6), unpadded.',
      },
      otpauth_uri: {
        type: 'string',
        format: 'uri',
        maxLength: 1024,
        pattern: '^otpauth://totp/[!#-;=?-\\[\\]-~]+$',
        description: 'The same secret as an `otpauth://` URI, for the QR code.',
      },
    },
    ['secret', 'otpauth_uri']
  ),
  answer: closedObject({ otp: sixDigitOtp }, ['otp']),
  errors: ['invalid_credentials'],
  amr: [],
  example: {
    params: { algorithm: 'SHA1', digits: 6, period: 30 },
    answer: { otp: '482913' },
    personal: {
      identifier: 'alice@example.com',
      secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
      otpauth_uri:
        'otpauth://totp/Example:alice%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30',
    },
    next: { step: 'recovery_codes' },
  },
});

/** One recovery code as the server shows it: 80 bits of base32, in four groups. */
const RECOVERY_CODE_PATTERN = '^[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}-[a-z2-7]{4}$';

export const recoveryCodes = defineStep({
  name: 'recovery_codes',
  transports: ['interaction'],
  summary: 'Shows a new set of recovery codes once.',
  description:
    'A new recovery-code set: issued at the first enrolment of a second factor, at the registration of a passkey-only account, and when the person regenerates the set (ADR-017 Decision 8). The codes are personal data: readable with the flow cookie while this step is current, and never after. The answer confirms the person saved them.',
  params: object(
    {
      count: { type: 'integer', enum: [10], description: 'How many codes the set holds.' },
    },
    ['count']
  ),
  personal: object(
    {
      codes: {
        type: 'array',
        description: 'The codes, each usable once.',
        minItems: 10,
        maxItems: 10,
        uniqueItems: true,
        items: {
          type: 'string',
          minLength: 19,
          maxLength: 19,
          pattern: RECOVERY_CODE_PATTERN,
          description: 'One code.',
        },
      },
    },
    ['codes']
  ),
  answer: closedObject(
    {
      acknowledged: {
        const: true,
        description: 'The person confirms they saved the codes. In a form post: `true`.',
      },
    },
    ['acknowledged']
  ),
  errors: [],
  amr: [],
  example: {
    params: { count: 10 },
    answer: { acknowledged: true },
    personal: {
      codes: [
        'k7qd-2mvw-x4ra-p6tn',
        'b3hs-q6ze-u2yc-m5lf',
        'w4na-j7rk-e3gx-t6pd',
        'c5ub-y2mh-r7kw-a4qs',
        'z6fe-n3td-g5vp-l2jx',
        'h2ry-s4ka-v6cm-d7wb',
        'q3lg-f5xn-k2ze-p4ut',
        'm7ws-b6dj-x3hr-e5ca',
        't4pk-a2qf-n6ly-g3vz',
        'r5ex-w7cu-j4mb-s2hd',
      ],
    },
    next: { redirect: EXAMPLE_REDIRECT },
  },
});
