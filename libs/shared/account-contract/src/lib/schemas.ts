import { FRESH_AUTHENTICATION_MAX_AGE_SECONDS } from './identifiers';
import { NOTICE_NAMES } from './notices';
import { ACCOUNT_PROBLEM_CODES, FIELD_ERROR_REASONS, PASSWORD_REJECTION_REASONS } from './problems';
import {
  absoluteUri,
  array,
  closedEnum,
  closedObject,
  dateTime,
  displayText,
  extensibleEnum,
  type JsonSchema,
  NEVER,
  object,
  openObject,
  whenEquals,
} from './schema-kit';
import { SECURITY_LOG_KIND_NAMES } from './security-log';

/**
 * The component schemas of the account API v1 contract (#588), in JSON Schema
 * 2020-12, the dialect of OpenAPI 3.1.
 *
 * The display rule of the Interaction API holds here too (ADR-019 Decision 6,
 * `schema-kit.ts`): the API sends
 * typed data from the auth server's records and never HTML, so every string is
 * an enum, a constant, or a bounded value with a pattern, and no schema takes
 * free text from the person. A value that reaches a screen is a display value,
 * annotated with where it comes from. The one exception is a password, which
 * takes any character: it is `format: password` and `writeOnly`, appears only
 * in a request and is never shown. `display-rules.test.ts` checks every schema.
 */

export const ref = (name: string): JsonSchema => ({ $ref: `#/components/schemas/${name}` });

/** A schema that also admits `null`: the same value, or nothing. */
export function nullable(schema: JsonSchema): JsonSchema {
  const type = schema['type'];
  if (typeof type !== 'string') throw new Error('nullable() takes a schema with one type');
  return { ...schema, type: [type, 'null'] };
}

/** An opaque id: a UUID string (the API conventions' id rule). */
export function uuid(description: string): JsonSchema {
  return {
    type: 'string',
    format: 'uuid',
    minLength: 36,
    maxLength: 36,
    pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
    description,
  };
}

/** An integer from 0 to `max`. */
export function count(max: number, description: string): JsonSchema {
  return { type: 'integer', minimum: 0, maximum: max, description };
}

const boolean = (description: string): JsonSchema => ({ type: 'boolean', description });

/** Hangul fillers: letters by category that render as nothing (`DISPLAY_TEXT_PATTERN` refuses them too). */
const FILLERS = '\\u115F\\u1160\\u3164\\uFFA0';

/** A string of exactly `length` decimal digits: a one-time code. */
export function digits(length: number, description: string): JsonSchema {
  return {
    type: 'string',
    minLength: length,
    maxLength: length,
    pattern: `^[0-9]{${length}}$`,
    description,
  };
}

/**
 * A password, the one value that takes any character: it is a credential, not
 * text. Never in a response (`writeOnly`), never shown. At most 256 UTF-16
 * code units, the raw length the password policy checks first (ADR-017
 * Decision 8).
 */
export function secret(description: string): JsonSchema {
  return {
    type: 'string',
    format: 'password',
    writeOnly: true,
    minLength: 1,
    maxLength: 256,
    description,
  };
}

/**
 * An email address, the person's own: no markup bracket, control, format or
 * space character, one `@` with something on either side, at most 254
 * characters (RFC 5321 §4.5.3.1.3). The server normalises it and checks it
 * further; the pattern only keeps a value displayable.
 */
export function emailAddress(description: string): JsonSchema {
  return {
    type: 'string',
    minLength: 3,
    maxLength: 254,
    pattern: `^[^<>@\\p{C}\\p{Z}${FILLERS}]{1,64}@[^<>@\\p{C}\\p{Z}${FILLERS}]{1,253}$`,
    'x-qauth-display': 'account',
    description,
  };
}

/**
 * Printable ASCII without space, `"`, `<`, `>` and `\`: what a client id or
 * a scope may hold here, so neither can carry markup to a screen.
 */
const TOKEN_CHARACTERS = '^[!#-;=?-\\[\\]-~]+$';

/** An OAuth `client_id`, which a client may make a URL (a Client ID Metadata Document client). */
export function clientId(description: string): JsonSchema {
  return {
    type: 'string',
    minLength: 1,
    maxLength: 2048,
    pattern: TOKEN_CHARACTERS,
    'x-qauth-declared': true,
    description,
  };
}

/** An RFC 6749 §3.3 scope token. */
const scopeToken: JsonSchema = {
  type: 'string',
  minLength: 1,
  maxLength: 256,
  pattern: TOKEN_CHARACTERS,
  description:
    'A scope: an RFC 6749 §3.3 `scope-token` without `<` and `>`, which no QAuth scope holds.',
};

/** An opaque paging cursor: base64url, as the server writes it. */
export const CURSOR_SCHEMA: JsonSchema = {
  type: 'string',
  minLength: 1,
  maxLength: 512,
  pattern: '^[A-Za-z0-9_-]+$',
  description:
    'The `nextCursor` of the previous page. Opaque: a client never builds or changes one.',
};

/** A list page of `item` (the API conventions' paging rule). */
function page(item: string, description: string): JsonSchema {
  return object(
    {
      items: array(ref(item), 0, 200, 'This page’s items, at most `limit`.'),
      nextCursor: {
        ...nullable(CURSOR_SCHEMA),
        description: 'The cursor of the next page; `null` on the last page.',
      },
    },
    ['items', 'nextCursor'],
    description
  );
}

/** The name of a profile field: lower camelCase, as the realm's profile schema names it. */
const PROFILE_FIELD_NAME_PATTERN = '^[a-z][a-zA-Z0-9]{0,63}$';

const profileValue = (description: string) => displayText('account', 255, description);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export const fieldErrorSchema = object(
  {
    pointer: {
      type: 'string',
      maxLength: 512,
      pattern: '^(?:/[A-Za-z0-9_]{1,64}){0,8}$',
      description:
        'An RFC 6901 JSON Pointer into the request body, or `/<name>` for a query or path parameter.',
    },
    reason: extensibleEnum(
      FIELD_ERROR_REASONS,
      '^[a-z][a-z0-9_]{0,63}$',
      64,
      'Why the field was refused. A console shows its own text, or the message the realm’s profile schema gives the field’s validator.'
    ),
  },
  ['pointer', 'reason'],
  'One refused field.'
);

export const problemSchema = openObject(
  {
    type: absoluteUri(
      2048,
      'RFC 9457 §3.1.1: `https://docs.qauth.dev/reference/problem-types/#` followed by the type’s slug. Not for branching.'
    ),
    title: {
      type: 'string',
      minLength: 1,
      maxLength: 64,
      pattern: '^[A-Za-z][A-Za-z -]*$',
      description:
        'The problem type’s title (RFC 9457 §3.1.3), the same in every document with this code. Not for branching, and not for a screen.',
    },
    status: {
      type: 'integer',
      minimum: 400,
      maximum: 599,
      description: 'The HTTP status, repeated.',
    },
    code: extensibleEnum(
      Object.keys(ACCOUNT_PROBLEM_CODES),
      '^[a-z][a-z0-9_]{0,63}$',
      64,
      'The error. Each error response of an operation lists the codes it may carry (`x-qauth-problem-codes`). A console shows its own text for it, and treats a code it does not know by its HTTP status: a minor release may add codes (ADR-019 Decision 7).'
    ),
    trace_id: {
      type: 'string',
      minLength: 1,
      maxLength: 128,
      pattern: '^[!#-;=?-~]+$',
      description:
        'The id the server logged the request under. A console shows it, so an operator can find the failure.',
    },
    errors: array(
      ref('FieldError'),
      1,
      64,
      'With `validation_error` and `unprocessable_content`: each refused field and why.'
    ),
    reasons: array(
      extensibleEnum(
        PASSWORD_REJECTION_REASONS,
        '^[a-z][a-z0-9_]{0,63}$',
        64,
        'One reason of the password policy or the breach list.'
      ),
      1,
      8,
      'With `weak_password`: why the new password was refused.'
    ),
    max_age: {
      type: 'integer',
      minimum: 0,
      maximum: FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
      description:
        'With `insufficient_user_authentication`: the `max_age` of the challenge (RFC 9470 §3), in seconds. Send the person to the authorization endpoint with it, then repeat the call.',
    },
    detail: { ...NEVER, description: 'Never sent: no prose.' },
    instance: { ...NEVER, description: 'Never sent.' },
  },
  ['type', 'title', 'status', 'code', 'trace_id'],
  'An RFC 9457 problem details document with a stable `code` and a `trace_id`, and no prose: no `detail`, no `instance`, and field errors as reason codes.',
  [
    whenEquals('code', ['insufficient_user_authentication'], { required: ['max_age'] }),
    whenEquals('code', ['weak_password'], { required: ['reasons'] }),
    whenEquals('code', ['validation_error', 'unprocessable_content'], { required: ['errors'] }),
  ]
);

// ---------------------------------------------------------------------------
// Profile
// ---------------------------------------------------------------------------

export const groupSchema = object(
  {
    id: uuid('The group’s id.'),
    name: displayText('realm', 64, 'The group’s name, as the realm’s admins set it.'),
  },
  ['id', 'name'],
  'A group the person belongs to. Read only: an admin assigns groups.'
);

export const profileFieldSchema = object(
  {
    name: {
      type: 'string',
      minLength: 1,
      maxLength: 64,
      pattern: PROFILE_FIELD_NAME_PATTERN,
      description: 'The field’s name in the realm’s profile schema, such as `givenName`.',
    },
    label: displayText('realm', 64, 'The field’s label, from the realm’s profile schema.'),
    help: displayText('realm', 280, 'The field’s help text, from the realm’s profile schema.'),
    type: extensibleEnum(
      ['text', 'date', 'choice'],
      '^[a-z][a-z0-9_]{0,31}$',
      32,
      'How the console asks for the value: free of markup in one line (`text`), an RFC 3339 full date (`date`), or one of `options` (`choice`). A console shows a type it does not know as read-only text.'
    ),
    required: boolean('Whether the realm requires a value.'),
    editable: boolean(
      'Whether the person may change it. A field only an admin edits, or one the server verified, is not.'
    ),
    verified: boolean('Whether the server verified the value, such as from an upstream provider.'),
    maxLength: {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      description: 'The longest value the field accepts.',
    },
    options: array(
      object(
        {
          value: {
            type: 'string',
            minLength: 1,
            maxLength: 64,
            pattern: '^[A-Za-z0-9_.-]+$',
            description: 'The value stored when the person picks it.',
          },
          label: displayText('realm', 64, 'The option’s label.'),
        },
        ['value', 'label']
      ),
      1,
      64,
      'For `choice`: the values the field accepts.'
    ),
    value: {
      ...nullable(profileValue('The value, or `null` when the field is empty.')),
    },
  },
  ['name', 'label', 'type', 'required', 'editable', 'maxLength', 'value'],
  'One field of the realm’s user profile schema, with the person’s value. Which fields exist, their types, rules and who may edit them are the realm’s (ADR-020, fork E); the contract shows them as a generic list.',
  [whenEquals('type', ['choice'], { required: ['options'] })]
);

export const profileSchema = object(
  {
    fields: array(
      ref('ProfileField'),
      0,
      64,
      'The fields the realm’s profile schema lets the person read, in its order. Never an identifier, the contact address or a claim the server sets itself (`sub`, `email`, `email_verified` and the others of ADR-020 fork E).'
    ),
    groups: array(ref('Group'), 0, 200, 'The groups the person belongs to, read only.'),
  },
  ['fields', 'groups'],
  'The person’s profile.'
);

export const profilePatchSchema = closedObject(
  {
    fields: {
      type: 'object',
      description:
        'New values by field name. `null` empties a field. A field the person may not edit, or one the schema does not hold, is refused with `unprocessable_content`.',
      propertyNames: { type: 'string', maxLength: 64, pattern: PROFILE_FIELD_NAME_PATTERN },
      maxProperties: 64,
      additionalProperties: nullable(profileValue('The new value.')),
    },
  },
  [],
  'A JSON Merge Patch (RFC 7396) of the profile’s values.'
);

// ---------------------------------------------------------------------------
// Sign-in methods
// ---------------------------------------------------------------------------

export const signInMethodsSchema = object(
  {
    password: object(
      {
        set: boolean('Whether the account has a password. A passkey-only account has none.'),
        changedAt: nullable(dateTime('When it was last set; `null` without one.')),
      },
      ['set', 'changedAt']
    ),
    passkeys: object({ count: count(100, 'How many passkeys are bound.') }, ['count']),
    totp: object({ enabled: boolean('Whether an authenticator app (TOTP) is bound.') }, [
      'enabled',
    ]),
    recoveryCodes: object({ remaining: count(10, 'How many unused recovery codes are left.') }, [
      'remaining',
    ]),
    linkedAccounts: object(
      {
        count: count(
          100,
          'How many upstream accounts and wallets are linked. Their lists are the Upstream login and Federation areas’.'
        ),
      },
      ['count']
    ),
    hasContactAddress: boolean(
      'Whether the account has a contact address. Without one, security notices go only to the security log.'
    ),
    freshAuthenticationFactor: closedEnum(
      ['pop', 'otp', 'pwd'],
      'The `amr` value a fresh authentication must hold: the account’s strongest bound factor. `pop` with a passkey bound, else `otp` with TOTP, else `pwd` (ADR-017 Decision 8).'
    ),
  },
  [
    'password',
    'passkeys',
    'totp',
    'recoveryCodes',
    'linkedAccounts',
    'hasContactAddress',
    'freshAuthenticationFactor',
  ],
  'Every way the person can sign in, at a glance.'
);

export const passwordChangeRequestSchema = closedObject(
  {
    currentPassword: secret('The password the account has now.'),
    newPassword: secret('The new password. The realm’s password policy and breach list apply.'),
  },
  ['currentPassword', 'newPassword'],
  'A password change.'
);

export const passkeySchema = object(
  {
    id: uuid('The passkey’s id: QAuth’s own, never the WebAuthn credential id.'),
    nickname: displayText('account', 64, 'The name the person gave it.'),
    provider: displayText(
      'server',
      64,
      'The authenticator’s maker, from its AAGUID and the server’s list. Absent when unknown.'
    ),
    backedUp: boolean('Whether the passkey syncs to other devices (the WebAuthn backup state).'),
    createdAt: dateTime('When it was added.'),
    lastUsedAt: nullable(dateTime('When it last signed in; `null` if never.')),
  },
  ['id', 'nickname', 'backedUp', 'createdAt', 'lastUsedAt'],
  'A bound passkey.'
);

export const passkeyPatchSchema = closedObject(
  { nickname: displayText('account', 64, 'The new name.') },
  [],
  'A JSON Merge Patch (RFC 7396) of a passkey: its name.'
);

export const totpEnrollmentSchema = object(
  {
    secret: {
      type: 'string',
      minLength: 32,
      maxLength: 32,
      pattern: '^[A-Z2-7]{32}$',
      description:
        'The shared secret, base32 (RFC 4648 §6) without padding: 160 bits. Shown once, for typing by hand; never sent again.',
    },
    otpauthUri: {
      type: 'string',
      minLength: 16,
      maxLength: 1024,
      pattern: '^otpauth://totp/[!#-;=?-~]+$',
      description:
        'The same secret as an `otpauth://totp/` URI with the realm as issuer, for the QR code. Shown once.',
    },
    algorithm: { type: 'string', const: 'SHA1', description: 'Fixed (ADR-020 §3).' },
    digits: { type: 'integer', const: 6, description: 'Fixed (ADR-020 §3).' },
    period: {
      type: 'integer',
      const: 30,
      description: 'Seconds per time step. Fixed (ADR-020 §3).',
    },
    expiresAt: dateTime('When the enrolment lapses unless confirmed.'),
    emailCode: closedEnum(
      ['required', 'not_required'],
      'Whether confirming also needs the 8-digit code QAuth just mailed to the account’s address: the first second factor of a password-only account does, unless the sign-in already proved that mailbox (ADR-017 Decision 8).'
    ),
  },
  ['secret', 'otpauthUri', 'algorithm', 'digits', 'period', 'expiresAt', 'emailCode'],
  'A started authenticator-app enrolment. Nothing is bound until it is confirmed with a first code.'
);

export const totpConfirmRequestSchema = closedObject(
  {
    code: digits(6, 'The first code the authenticator app shows.'),
    emailCode: digits(
      8,
      'The code mailed to the account’s address, when the enrolment asks for one.'
    ),
  },
  ['code'],
  'The confirmation of an authenticator-app enrolment.'
);

export const recoveryCodeSetSchema = object(
  {
    codes: array(
      {
        type: 'string',
        minLength: 19,
        maxLength: 19,
        pattern: '^[A-Z2-7]{4}(?:-[A-Z2-7]{4}){3}$',
        description:
          'One code: 16 base32 characters (80 bits from a CSPRNG) in four groups. It works once.',
      },
      10,
      10,
      'The ten codes. Shown once: the server keeps only their hashes.'
    ),
    issuedAt: dateTime('When the set was issued. Every earlier set stopped working then.'),
  },
  ['codes', 'issuedAt'],
  'A new set of recovery codes (ADR-017 Decision 8).'
);

export const totpConfirmResultSchema = object(
  {
    enabledAt: dateTime('When the authenticator app was bound.'),
    recoveryCodes: ref('RecoveryCodeSet'),
  },
  ['enabledAt'],
  'A bound authenticator app. `recoveryCodes` is present when it was the account’s first second factor, which issues the first set.'
);

export const recoveryCodeStatusSchema = object(
  {
    remaining: count(10, 'How many unused codes are left.'),
    issuedAt: nullable(dateTime('When the current set was issued; `null` without one.')),
  },
  ['remaining', 'issuedAt'],
  'The account’s recovery codes, without the codes.'
);

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

export const deviceSchema = object(
  {
    label: displayText(
      'declared',
      96,
      'A label from the user agent, such as `Firefox on Linux`. The device declared it.'
    ),
  },
  ['label'],
  'The device a session or an entry came from.'
);

export const locationSchema = object(
  {
    country: {
      type: 'string',
      minLength: 2,
      maxLength: 2,
      pattern: '^[A-Z]{2}$',
      description: 'The country, ISO 3166-1 alpha-2.',
    },
    region: displayText('server', 64, 'The region, when known.'),
    city: displayText('server', 64, 'The city, when known.'),
  },
  ['country'],
  'An approximate location from an offline address database. Never the address itself.'
);

export const sessionSchema = object(
  {
    id: uuid('The session’s id: its record’s, never the cookie value.'),
    current: boolean(
      'Whether the token in this request was issued through this session (its `sid`).'
    ),
    createdAt: dateTime('When the session started.'),
    lastSeenAt: dateTime('When it was last used.'),
    device: ref('Device'),
    location: ref('Location'),
  },
  ['id', 'current', 'createdAt', 'lastSeenAt', 'device'],
  'A browser session of the account. `location` is absent when unknown.'
);

export const endAllSessionsRequestSchema = closedObject(
  {
    keepCurrent: {
      type: 'boolean',
      default: false,
      description: 'Keep the session this request’s token was issued through. Default: end it too.',
    },
  },
  [],
  '"Sign out everywhere".'
);

// ---------------------------------------------------------------------------
// Security log
// ---------------------------------------------------------------------------

export const securityLogKindSchema = closedEnum(
  SECURITY_LOG_KIND_NAMES,
  'What happened. A closed list: a console may branch on every value. Each kind is built from QAuth events (the event types the docs page names).'
);

export const clientReferenceSchema = object(
  {
    client_id: clientId('The app’s OAuth `client_id`.'),
    client_name: displayText('declared', 255, 'The name the app declared about itself.'),
  },
  ['client_id'],
  'The app an entry concerns.'
);

export const securityLogEntrySchema = object(
  {
    id: uuid('The entry’s id: the id of the event it was built from.'),
    kind: ref('SecurityLogKind'),
    occurredAt: dateTime('When it happened.'),
    initiator: closedEnum(
      ['user', 'admin', 'policy', 'system'],
      'Who caused it, as CAEP 1.0 §2 names it: the person, an admin, a realm policy, or QAuth itself (a credential disabled after too many attempts).'
    ),
    delegated: boolean(
      'Whether it came through an act-chain token: an admin or an agent acting for the person (ADR-019 Decision 7).'
    ),
    device: ref('Device'),
    location: ref('Location'),
    client: ref('ClientReference'),
    credentialType: closedEnum(
      ['password', 'passkey', 'totp'],
      'For `credential_added`, `credential_removed` and `credential_disabled`: which credential.'
    ),
    reportable: boolean(
      'Whether "this wasn’t me" may be reported on it: a sign-in not yet reported.'
    ),
  },
  ['id', 'kind', 'occurredAt', 'initiator', 'delegated', 'reportable'],
  'One entry of the security log. `device`, `location` and `client` are present when the event recorded them; the raw IP address never is.',
  [
    whenEquals('kind', ['credential_added', 'credential_removed', 'credential_disabled'], {
      required: ['credentialType'],
    }),
  ]
);

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------

export const addressesSchema = object(
  {
    signInAddress: nullable(
      emailAddress(
        'The address the account signs in with; `null` for an account with none, such as a passkey-only account.'
      )
    ),
    contactAddress: nullable(
      emailAddress(
        'Where notices go: the sign-in address, or a contact address added to an account without one; `null` when there is none.'
      )
    ),
    signInAddressChange: closedEnum(
      ['allowed', 'blocked'],
      'Whether the realm lets the person change the sign-in address (`blocked`: only an admin can).'
    ),
  },
  ['signInAddress', 'contactAddress', 'signInAddressChange'],
  'The account’s identifier and contact address. In 1.0 an identifier is an email address (ADR-017).'
);

const addressUse = closedEnum(
  ['sign_in', 'contact'],
  'Which address changes: the one the account signs in with, or the contact address of an account that signs in without one.'
);

export const addressChangeRequestSchema = closedObject(
  { use: addressUse, address: emailAddress('The new address.') },
  ['use', 'address'],
  'The start of an address change. An 8-digit code goes to the new address.'
);

export const addressChangeSchema = object(
  { use: addressUse, expiresAt: dateTime('When the mailed code lapses.') },
  ['use', 'expiresAt'],
  'A started address change. The answer is the same whether or not the new address belongs to another account.'
);

export const addressChangeConfirmRequestSchema = closedObject(
  { code: digits(8, 'The code mailed to the new address.') },
  ['code'],
  'The confirmation of an address change.'
);

// ---------------------------------------------------------------------------
// Connected apps
// ---------------------------------------------------------------------------

export const consentSchema = object(
  {
    id: uuid('The consent’s id.'),
    client_id: clientId(
      'The app’s OAuth `client_id`, which may be a URL (a Client ID Metadata Document client).'
    ),
    client_name: displayText('declared', 255, 'The name the app declared about itself.'),
    scopes: array(scopeToken, 0, 64, 'The scopes the person granted.'),
    grantedAt: dateTime('When the consent was first given.'),
  },
  ['id', 'client_id', 'client_name', 'scopes', 'grantedAt'],
  'A connected app: an active consent the person gave. `client_name` is what the app declared about itself, and a console marks it as declared (ADR-019 Decision 6). A later version may add the verified display data the Interaction API shows for a client, as an optional member.'
);

// ---------------------------------------------------------------------------
// Deletion
// ---------------------------------------------------------------------------

export const deletionPreviewSchema = object(
  {
    allowed: boolean(
      'Whether the realm lets the person delete the account. When it does not, only an admin deletes.'
    ),
    sessions: count(10_000, 'Sessions that end.'),
    consents: count(10_000, 'Consents that go, with their refresh tokens.'),
    credentials: count(1_000, 'Sign-in methods that go: password, passkeys, TOTP, recovery codes.'),
    clients: count(10_000, 'Developer clients the account owns, which go with it.'),
    apiKeys: count(10_000, 'API keys of those clients, which stop working.'),
  },
  ['allowed', 'sessions', 'consents', 'credentials', 'clients', 'apiKeys'],
  'What deleting the account removes. Audit and event records stay, apart from the account (ADR-018 §3).'
);

/** The value a deletion request confirms with. */
export const DELETION_CONFIRMATION = 'delete-account';

export const deletionRequestSchema = closedObject(
  {
    confirmation: {
      type: 'string',
      const: DELETION_CONFIRMATION,
      description:
        'Sent only after the person typed the confirmation the console asked for, in their language. The constant keeps a stray call from deleting.',
    },
  },
  ['confirmation'],
  'An account deletion.'
);

// ---------------------------------------------------------------------------
// Notifications
// ---------------------------------------------------------------------------

export const noticePreferenceSchema = object(
  {
    notice: closedEnum(NOTICE_NAMES, 'The notice.'),
    mandatory: boolean('Whether it always goes out: no setting switches it off.'),
    enabled: boolean('Whether the account receives it now.'),
  },
  ['notice', 'mandatory', 'enabled'],
  'One security notice.'
);

export const notificationPreferencesSchema = object(
  {
    delivery: closedEnum(
      ['email', 'security_log'],
      'Where notices go: the contact address, or only the security log for an account without one.'
    ),
    notices: array(
      ref('NoticePreference'),
      NOTICE_NAMES.length,
      NOTICE_NAMES.length,
      'Every notice, in a fixed order.'
    ),
  },
  ['delivery', 'notices'],
  'The security notices the account receives. Which may be switched off is the realm’s setting (ADR-020 §3); this version reads them.'
);

// ---------------------------------------------------------------------------
// Pages
// ---------------------------------------------------------------------------

export const PAGES = {
  PasskeyPage: page('Passkey', 'A page of the account’s passkeys, newest first.'),
  SessionPage: page('Session', 'A page of the account’s sessions, most recently used first.'),
  SecurityLogPage: page('SecurityLogEntry', 'A page of the security log, newest first.'),
  ConsentPage: page(
    'Consent',
    'A page of connected apps, by when each consent was first given, newest first.'
  ),
} as const;
