import { base64url, closedObject, EMPTY_OBJECT, host, object } from '../schema-kit';
import { defineStep } from '../step-definition';
import {
  accountIdentifier,
  identifierPersonal,
  loginHint,
  sixDigitOtp,
  webauthnResponse,
} from './shared';

/**
 * The sign-in steps: who is signing in, and the factors that prove it.
 * `identifier`, `password`, `captcha`, `webauthn_get` and `totp` are the
 * steps of ADR-017 Decision 3 and are served by both transports;
 * `recovery_code` and `select_account` only by the Interaction API.
 */

/** The authorization response the examples end in. */
export const EXAMPLE_REDIRECT =
  'https://app.example.com/callback?code=uY29tL2F1dGhlbnRpY2F0aW9u&state=af0ifjsldkj&iss=https%3A%2F%2Fauth.example.com';

/** A stand-in for a 32-byte random value, base64url. */
export const EXAMPLE_CHALLENGE = 'Qm9vbGVhbi1ub3QtYS1yZWFsLWNoYWxsZW5nZS0zMmI';

export const identifier = defineStep({
  name: 'identifier',
  transports: ['interaction', 'fipa'],
  summary: 'Asks who is signing in.',
  description:
    'Identifier-first sign-in (ADR-020 §3). Every identifier, known or unknown, gets the same next step, so the screen reveals nothing about which accounts exist (ADR-017 Decision 4). Offered as an alternative of a later step, it is the account switch ("Not you?", "Use another account"): answering it ends the interaction and starts a new one for the same authorization request, and the result is a redirect to the ceremony app’s page of the new interaction. Nothing proved for the first account carries over (#592). After the person signed in during the interaction, the switch also ends the browser session that sign-in started and, when the server can check the browser’s session cookie, the session it names if that belongs to the same account (a sign-in again in another tab), and clears the cookie when it names one of them (#896). A cookie session of another account stays. A switch before anyone signed in ends no session, so a browser already signed in when the interaction started stays signed in (#964).',
  params: EMPTY_OBJECT,
  personal: EMPTY_OBJECT,
  answer: closedObject({ login_hint: loginHint }, ['login_hint']),
  errors: [],
  amr: [],
  example: {
    params: {},
    answer: { login_hint: 'alice@example.com' },
    alternatives: ['webauthn_get'],
    next: { step: 'password' },
  },
});

export const password = defineStep({
  name: 'password',
  transports: ['interaction', 'fipa'],
  summary: 'Asks for the password.',
  description:
    'The password factor. A rejected password, an unknown account and a disabled account give the same `invalid_credentials`, after the same timing floor (ADR-017 Decisions 3 and 4). Works without JavaScript: the form posts straight to the auth server with the step’s CSRF value (ADR-019 Decision 5).',
  params: EMPTY_OBJECT,
  personal: identifierPersonal,
  answer: closedObject(
    {
      password: {
        type: 'string',
        minLength: 1,
        maxLength: 256,
        description:
          'The password. The server refuses one longer than 256 UTF-16 code units before anything else (ADR-017 Decision 8).',
      },
      login_hint: {
        ...loginHint,
        description: `${String(loginHint['description'])} Sent only when the transaction holds no identifier yet: a page that asks for both at once.`,
      },
    },
    ['password']
  ),
  errors: ['invalid_credentials'],
  amr: ['pwd'],
  example: {
    params: {},
    error: 'invalid_credentials',
    answer: { password: 'correct horse battery staple x' },
    personal: { identifier: 'alice@example.com' },
    alternatives: ['identifier', 'webauthn_get', 'password_reset', 'recovery_code'],
    next: { redirect: EXAMPLE_REDIRECT },
  },
});

export const captcha = defineStep({
  name: 'captcha',
  transports: ['interaction', 'fipa'],
  summary: 'Asks for a bot challenge answer.',
  description:
    'A bot challenge, when a soft threshold requires one; the pending step resumes after it (ADR-017 Decisions 4 and 7). By default the built-in proof of work, whose script the ceremony app serves from the realm origin. An operator may name a hosted provider for the sign-up and sign-in pages only (ADR-019 Decision 5). A required challenge needs JavaScript and is never skipped.',
  params: {
    description: 'The challenge to solve: the built-in proof of work, or a hosted provider.',
    oneOf: [
      object(
        {
          provider: { const: 'pow', description: 'The built-in proof of work.' },
          challenge: base64url(22, 128, 'The puzzle the engine issued.'),
          difficulty: {
            type: 'integer',
            minimum: 1,
            maximum: 32,
            description: 'How many leading zero bits the answer must produce.',
          },
        },
        ['provider', 'challenge', 'difficulty']
      ),
      object(
        {
          provider: { const: 'hosted', description: 'A hosted provider the operator named.' },
          name: {
            type: 'string',
            minLength: 1,
            maxLength: 32,
            pattern: '^[a-z][a-z0-9_-]{0,31}$',
            description: 'The name the operator gave the hosted provider.',
          },
          site_key: {
            type: 'string',
            minLength: 1,
            maxLength: 256,
            pattern: '^[A-Za-z0-9._-]+$',
            description: 'The provider’s public site key.',
          },
        },
        ['provider', 'name', 'site_key']
      ),
    ],
  },
  personal: EMPTY_OBJECT,
  answer: closedObject(
    {
      captcha_token: {
        type: 'string',
        minLength: 1,
        maxLength: 4096,
        pattern: '^[!-~]+$',
        description:
          'The solution, or the provider’s token: printable ASCII, so 4096 characters are 4096 bytes.',
      },
    },
    ['captcha_token']
  ),
  errors: ['captcha_failed'],
  amr: [],
  example: {
    params: { provider: 'pow', challenge: EXAMPLE_CHALLENGE, difficulty: 18 },
    answer: { captcha_token: 'AAAAAAAABl9x' },
    next: { step: 'password' },
  },
});

export const webauthnGet = defineStep({
  name: 'webauthn_get',
  transports: ['interaction', 'fipa'],
  summary: 'Asks for a passkey.',
  description:
    'Passkey sign-in: the WebAuthn Level 3 request options as JSON, for `PublicKeyCredential.parseRequestOptionsFromJSON()`. Discoverable credentials only: the options never carry `allowCredentials`, so the step read reveals no account’s passkeys (ADR-017 Decision 4, ADR-019 Decision 6). The engine checks that the passkey belongs to the transaction’s account. The RP ID is the realm’s host (ADR-019 Decision 2). Needs JavaScript.',
  params: object(
    {
      challenge: base64url(43, 128, 'The challenge, at least 32 random bytes.'),
      rpId: host('The relying party ID: the realm’s host.'),
      timeout: {
        type: 'integer',
        minimum: 1000,
        maximum: 600000,
        description: 'How long the ceremony may take, in milliseconds.',
      },
      userVerification: {
        const: 'required',
        description: 'The server refuses an assertion without user verification.',
      },
    },
    ['challenge', 'rpId', 'userVerification']
  ),
  personal: identifierPersonal,
  answer: closedObject({ webauthn_response: webauthnResponse(8192, 'assertion') }, [
    'webauthn_response',
  ]),
  errors: ['invalid_credentials'],
  amr: ['pop', 'mfa'],
  example: {
    params: {
      challenge: EXAMPLE_CHALLENGE,
      rpId: 'auth.example.com',
      timeout: 300000,
      userVerification: 'required',
    },
    answer: {
      webauthn_response: JSON.stringify({
        id: 'mC1lKXgSi0S3vW2mU1Nwhg',
        rawId: 'mC1lKXgSi0S3vW2mU1Nwhg',
        type: 'public-key',
        response: {
          clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0',
          authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAQ',
          signature: 'MEUCIQDzVOkaFj9Kf2m9VE3e3Jx1yX2w',
          userHandle: 'b2Zmc2V0LXVzZXItaGFuZGxl',
        },
        authenticatorAttachment: 'platform',
        clientExtensionResults: {},
      }),
    },
    personal: { identifier: 'alice@example.com' },
    next: { redirect: EXAMPLE_REDIRECT },
  },
});

export const totp = defineStep({
  name: 'totp',
  transports: ['interaction', 'fipa'],
  summary: 'Asks for the code of the authenticator app.',
  description:
    'A TOTP second factor (RFC 6238) with the fixed parameters of ADR-020 §3: SHA-1, six digits, 30 seconds, one step of tolerance. An accepted code is never accepted twice (ADR-017 Decision 8). Works without JavaScript.',
  params: object(
    {
      digits: { type: 'integer', enum: [6], description: 'How many digits the code has.' },
    },
    ['digits']
  ),
  personal: identifierPersonal,
  answer: closedObject({ otp: sixDigitOtp }, ['otp']),
  errors: ['invalid_credentials'],
  amr: ['otp'],
  example: {
    params: { digits: 6 },
    answer: { otp: '482913' },
    personal: { identifier: 'alice@example.com' },
    alternatives: ['recovery_code'],
    next: { redirect: EXAMPLE_REDIRECT },
  },
});

export const recoveryCode = defineStep({
  name: 'recovery_code',
  transports: ['interaction'],
  summary: 'Asks for one of the account’s recovery codes.',
  description:
    'A recovery code stands in for a second factor after the first, or for the passkey of a passkey-only account. Only the hosted pages redeem one; the FiPA endpoint answers `redirect_to_web` for that path. It adds no `amr` value and never `mfa`, so a policy that needs a second factor makes the person bind a new one before the transaction completes (ADR-017 Decisions 4 and 8). Works without JavaScript.',
  params: EMPTY_OBJECT,
  personal: identifierPersonal,
  answer: closedObject(
    {
      recovery_code: {
        type: 'string',
        minLength: 16,
        maxLength: 39,
        pattern: '^[A-Za-z0-9 -]+$',
        description:
          'The code as the person typed it. The server ignores case, spaces and dashes before comparing.',
      },
    },
    ['recovery_code']
  ),
  errors: ['invalid_credentials'],
  amr: [],
  example: {
    params: {},
    answer: { recovery_code: 'k7qd-2mvw-x4ra-p6tn' },
    personal: { identifier: 'alice@example.com' },
    next: { redirect: EXAMPLE_REDIRECT },
  },
});

export const selectAccount = defineStep({
  name: 'select_account',
  transports: ['interaction'],
  summary: 'Asks which signed-in account to continue with.',
  description:
    'The account chooser for `prompt=select_account`, when the browser holds sessions for several accounts of the realm (ADR-019 Decision 3, ADR-020 §3). The list is personal data. "Use another account" answers the `identifier` step, offered beside this one: that starts a new interaction for the same authorization request, and the result is a redirect to its page (#592). Needs JavaScript, to read the list.',
  params: EMPTY_OBJECT,
  personal: object(
    {
      accounts: {
        type: 'array',
        description: 'The accounts the browser holds a session for, the current one first.',
        minItems: 1,
        maxItems: 16,
        items: object(
          {
            account: base64url(
              22,
              64,
              'An opaque reference to the account’s session, valid for this interaction only.'
            ),
            identifier: accountIdentifier,
            current: {
              type: 'boolean',
              description: 'Whether this is the account the browser last used.',
            },
          },
          ['account', 'identifier', 'current']
        ),
      },
    },
    ['accounts']
  ),
  answer: closedObject(
    {
      account: base64url(22, 64, 'The `account` reference of the chosen entry.'),
    },
    ['account']
  ),
  errors: ['account_unavailable'],
  amr: [],
  example: {
    params: {},
    answer: { account: 'c2Vzc2lvbi1yZWYtMDAwMDAx' },
    personal: {
      accounts: [
        { account: 'c2Vzc2lvbi1yZWYtMDAwMDAx', identifier: 'alice@example.com', current: true },
        { account: 'c2Vzc2lvbi1yZWYtMDAwMDAy', identifier: 'alice@work.example', current: false },
      ],
    },
    alternatives: ['identifier'],
    next: { redirect: EXAMPLE_REDIRECT },
  },
});
