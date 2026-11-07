import {
  array,
  base64url,
  closedEnum,
  closedObject,
  displayText,
  EMPTY_OBJECT,
  host,
  httpsUrl,
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

/**
 * The sign-in steps: who is signing in, and the factors that prove it.
 * `identifier`, `password`, `captcha`, `webauthn_get` and `totp` are the
 * steps of ADR-017 Decision 3 and are served by both transports;
 * `recovery_code`, `select_account`, `upstream` and `upstream_link` only by the
 * Interaction API.
 */

/** The authorization response the examples end in. */
export const EXAMPLE_REDIRECT =
  'https://app.example.com/callback?code=uY29tL2F1dGhlbnRpY2F0aW9u&state=af0ifjsldkj&iss=https%3A%2F%2Fauth.example.com';

/** The identifier step's personal data: the request's `login_hint` as a prefill (#628). */
const identifierPrefill = object(
  {
    login_hint: displayText(
      'declared',
      254,
      "The authorization request's `login_hint` (OpenID Connect Core 1.0 §3.1.2.1), for the screen to pre-fill the identifier field with (#628). The client chose it, so it is only a suggestion: the person answers the step with it or with another identifier, and the server checks that answer as it checks any other. Absent when the request carried none or one that is no display value, and after an account switch."
    ),
  },
  [],
  'What the screen pre-fills the identifier field with.'
);

/** A stand-in for a 32-byte random value, base64url. */
export const EXAMPLE_CHALLENGE = 'Qm9vbGVhbi1ub3QtYS1yZWFsLWNoYWxsZW5nZS0zMmI';

export const identifier = defineStep({
  name: 'identifier',
  transports: ['interaction', 'fipa'],
  summary: 'Asks who is signing in.',
  description:
    'Identifier-first sign-in (ADR-020 §3). Every identifier, known or unknown, gets the same next step, so the screen reveals nothing about which accounts exist (ADR-017 Decision 4). Offered as an alternative of a later step, it is the account switch: answering it ends the interaction and starts a new one for the same authorization request, and the result is a redirect to the ceremony app’s page of the new interaction. Nothing proved for the first account carries over (#592). Beside `select_account` it is "Use another account", which ends no session: it adds an account, and the accounts the chooser lists stay signed in (ADR-019 Decision 3). Beside any other step it is "Not you?", which also signs the browser out of the account the screen shows, and of no other account, so that the next person or the next app on a shared device does not continue as that account; its label says that it signs out (#964). The account shown is the one a sign-in during the interaction proved, the signed-in user a consent is for or, while nobody has signed in during the interaction, the account the identifier the person gave names. Its sessions that end: the one a sign-in during the interaction started (#896); the session the browser was already signed in with when the interaction started, such as for a consent or a sign-in the app asked for again, when it is that account’s (#964); and, when the server can check the browser’s session cookie, the session it names if that belongs to the same account (a sign-in again in another tab). The cookie is cleared when it names one of them. A session of another account stays.',
  params: EMPTY_OBJECT,
  personal: identifierPrefill,
  answer: closedObject({ login_hint: loginHint }, ['login_hint']),
  errors: [],
  amr: [],
  example: {
    params: {},
    answer: { login_hint: 'alice@example.com' },
    personal: { login_hint: 'alice@example.com' },
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
    'The account chooser for `prompt=select_account`, when the browser holds sessions for several accounts of the realm (ADR-019 Decision 3, ADR-020 §3). The list is personal data. "Use another account" answers the `identifier` step, offered beside this one: that starts a new interaction for the same authorization request, and the result is a redirect to its page (#592). It ends no session: the accounts the list shows stay signed in (#964). Needs JavaScript, to read the list.',
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

/** The pattern of an upstream provider's name: the AuthMethod `type` (`oidc_corp`). */
const UPSTREAM_PROVIDER_PATTERN = '^[a-z][a-z0-9_]{0,62}$';

/** An upstream provider's name, as the list carries it and the answer names it. */
function upstreamProvider(description: string) {
  return {
    type: 'string',
    minLength: 1,
    maxLength: 63,
    pattern: UPSTREAM_PROVIDER_PATTERN,
    description,
  };
}

export const upstream = defineStep({
  name: 'upstream',
  transports: ['interaction'],
  summary: 'Offers sign-in through an upstream identity provider.',
  description:
    'The person picks one of the realm’s upstream identity providers: generic OpenID Connect, or an AuthMethod plugin. It is offered beside the `identifier` step, before anyone is named, alike for every account (ADR-017 Decision 4). An answer names one provider of the list; the answer’s result is a redirect to the provider (`result: redirect`, or `303` to it for a form post). The provider sends the browser back to `/upstream/<provider>/callback` on the realm host, which checks the answer against the transaction kept server-side for this interaction and its flow cookie, signs in the account that holds that upstream identity, or, for an identity no account holds, asks at the `upstream_link` step whether it starts a new account or joins an existing one, and continues the interaction: the next step’s ceremony page, or the final redirect. A sign-in through a provider ranks with the password in the downgrade rule, below a passkey (ADR-017 Decision 4), and adds no `amr` value. A provider an operator hides is not listed here and stays reachable through the authorization request’s `qauth_upstream` parameter. Works without JavaScript: each provider is a button of a plain form post.',
  params: object(
    {
      providers: array(
        object(
          {
            provider: upstreamProvider('The provider’s name, which the answer names.'),
            name: displayText(
              'realm',
              64,
              'The provider’s name as the operator set it, for its button.'
            ),
            icon: httpsUrl(
              2048,
              'An absolute `https` URL on the realm origin of a PNG icon for the button. Nothing supplies one yet (#714).'
            ),
          },
          ['provider', 'name']
        ),
        1,
        16,
        'The realm’s upstream identity providers, in the order the screen shows them.'
      ),
    },
    ['providers']
  ),
  personal: EMPTY_OBJECT,
  answer: closedObject(
    { provider: upstreamProvider('The `provider` of the entry the person picked.') },
    ['provider']
  ),
  errors: ['provider_unavailable'],
  amr: [],
  example: {
    params: { providers: [{ provider: 'oidc_corp', name: 'Example Corp' }] },
    answer: { provider: 'oidc_corp' },
    alternatives: ['identifier'],
    next: {
      redirect:
        'https://idp.example.com/authorize?response_type=code&client_id=qauth&state=Qm9vbGVhbi1ub3QtYS1yZWFsLXN0YXRl',
    },
  },
});

export const upstreamLink = defineStep({
  name: 'upstream_link',
  transports: ['interaction'],
  summary:
    'Asks whether an upstream identity QAuth does not know starts a new account or joins an existing one.',
  description:
    'Shown once an upstream identity provider proved an identity no account of the realm holds (#670; ADR-020 §3). The person picks a new account with that identity, which only a realm that allows sign-up offers (`create`), or the account they already have, which they then sign in to in this interaction with its own factors and its MFA policy: the `identifier` step, and every step that account’s sign-in asks for. The identity joins that account only once that sign-in completes, in the same browser and the same interaction; no other way to sign in is offered meanwhile, neither another provider nor a password reset. Nothing on the step names the identity or the account: no address and no hint, and no account is ever found by an attribute such as an email address. Works without JavaScript: each choice is a button of a plain form post.',
  params: object(
    {
      provider: object(
        {
          provider: upstreamProvider('The provider’s name: the AuthMethod `type`.'),
          name: displayText(
            'realm',
            64,
            'The provider’s name as the operator set it, for the screen’s text.'
          ),
        },
        ['provider', 'name']
      ),
      create: {
        type: 'boolean',
        description:
          'Whether the person may start a new account with the identity: the realm allows sign-up. `false` offers the existing account only.',
      },
    },
    ['provider', 'create']
  ),
  personal: EMPTY_OBJECT,
  answer: closedObject(
    {
      decision: closedEnum(
        ['create', 'link'],
        'A new account with the identity, or the existing account the person signs in to next.'
      ),
    },
    ['decision']
  ),
  errors: [],
  amr: [],
  example: {
    params: { provider: { provider: 'oidc_corp', name: 'Example Corp' }, create: true },
    answer: { decision: 'link' },
    next: { step: 'identifier' },
  },
});
