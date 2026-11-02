import { EXAMPLE_CLIENT } from './client-display';
import type { ActChainRule, FreshAuthenticationRule } from './identifiers';
import { NOTICE_NAMES, NOTICES } from './notices';
import { ACCOUNT_PROBLEM_CODES, type AccountProblemCodeName } from './problems';
import { DELETION_CONFIRMATION } from './schemas';

/**
 * Every operation of the account API v1 contract (#588), with what ADR-019
 * Decision 7 and ADR-017 Decision 8 say about each: the permission it will
 * need, whether it needs fresh authentication, whether it refuses an
 * act-chain token, and one example request and response. `openapi.ts` turns
 * the table into the document; the tests read it to check the examples and the
 * rules.
 */

export const ACCOUNT_TAGS = {
  Profile: 'The person’s profile fields and groups.',
  'Sign-in methods': 'Password, passkeys, the authenticator app (TOTP) and recovery codes.',
  Sessions: 'Where the person is signed in, and "sign out everywhere".',
  'Security log':
    'The last 90 days of sign-ins, new devices and security changes, and "this wasn’t me".',
  Addresses: 'The address the account signs in with, and its contact address.',
  'Connected apps': 'The apps the person consented to, and their revocation.',
  Account: 'Deleting the account.',
  Notifications: 'The security notices the account receives.',
} as const;

export type AccountTag = keyof typeof ACCOUNT_TAGS;

export type HttpMethod = 'get' | 'post' | 'patch' | 'delete';

/** A request body: its media type and the component that describes it. */
export interface OperationBody {
  readonly mediaType: 'application/json' | 'application/merge-patch+json';
  readonly schema: string;
  readonly required: boolean;
}

/** The success response: its status, and the component of its body when it has one. */
export interface OperationSuccess {
  readonly status: 200 | 201 | 202 | 204;
  readonly description: string;
  readonly schema?: string;
  /** Whether it carries the resource's `ETag` (a read of one resource, or its update). */
  readonly etag?: boolean;
}

/** One example exchange: the request's parameters and body, and the success response. */
export interface OperationExample {
  readonly summary: string;
  readonly pathParams?: Readonly<Record<string, string>>;
  readonly query?: Readonly<Record<string, string | number>>;
  readonly ifMatch?: string;
  readonly body?: unknown;
  readonly response?: unknown;
  readonly etag?: string;
}

export interface AccountOperation {
  /** `account.<resource>.<verb>`: the account and developer families share the server's document. */
  readonly id: string;
  readonly method: HttpMethod;
  /** The path after the prefix, with OpenAPI `{name}` parameters. */
  readonly path: string;
  readonly tag: AccountTag;
  readonly summary: string;
  readonly description: string;
  readonly class: 'read' | 'write';
  /** The permission the operation will need (#933); not enforced yet. */
  readonly permission: string;
  readonly freshAuthentication: FreshAuthenticationRule;
  readonly actChain: ActChainRule;
  /** Path parameters, each an id: `{ name: description }`. */
  readonly pathParameters?: Readonly<Record<string, string>>;
  /** A list: cursor paging, and the list's own filters. */
  readonly list?: { readonly filters?: readonly 'kind'[] };
  /** An update: `If-Match` required, `ETag` back. */
  readonly conditional?: boolean;
  readonly body?: OperationBody;
  readonly success: OperationSuccess;
  /** Codes beyond the ones every operation of its shape answers ({@link operationCodes}). */
  readonly codes?: readonly AccountProblemCodeName[];
  readonly example: OperationExample;
}

// ---------------------------------------------------------------------------
// Example values
// ---------------------------------------------------------------------------

export const EXAMPLE_TRACE_ID = '0b9e2c4f-6a1d-4c3e-9f2a-7d5b8e1c3a60';
const PASSKEY_ID = '019a2b3c-4d5e-7f60-8a9b-0c1d2e3f4a5b';
const SESSION_ID = '019a2b3c-5e6f-7a8b-9c0d-1e2f3a4b5c6d';
const OTHER_SESSION_ID = '019a2a10-77b2-7c31-a4d5-e6f708192a3b';
const ENTRY_ID = '019a3f0e-1b2c-7d3e-8f4a-5b6c7d8e9f01';
const CONSENT_ID = '019a1e5d-2c3b-7a49-b8c7-d6e5f4a3b2c1';
const GROUP_ID = '0193d6a2-8f41-7b2c-9d3e-4f5a6b7c8d9e';
const ETAG = '"5d41402abc4b2a76"';
const NEXT_ETAG = '"7d793037a0760186"';
const LAPTOP = { label: 'Firefox on Linux' };
const PHONE = { label: 'Safari on iPhone' };
const BERLIN = { country: 'DE', region: 'Berlin', city: 'Berlin' };

const PROFILE = {
  fields: [
    {
      name: 'givenName',
      label: 'Given name',
      type: 'text',
      required: true,
      editable: true,
      maxLength: 64,
      value: 'Ada',
    },
    {
      name: 'familyName',
      label: 'Family name',
      type: 'text',
      required: false,
      editable: true,
      maxLength: 64,
      value: 'Lovelace',
    },
    {
      name: 'department',
      label: 'Department',
      help: 'Set by your organisation.',
      type: 'choice',
      required: false,
      editable: false,
      maxLength: 32,
      options: [
        { value: 'research', label: 'Research' },
        { value: 'operations', label: 'Operations' },
      ],
      value: 'research',
    },
  ],
  groups: [{ id: GROUP_ID, name: 'Research' }],
};

const RECOVERY_CODES = {
  codes: [
    'ZSOB-UHWE-YYKG-ZBBD',
    'QCE2-MSJG-H6QW-P7E5',
    '2YWI-YW62-RZGJ-DGNL',
    'NBZ6-4WV3-G3L6-7EBC',
    'EEO7-XCGT-SKJS-YHYE',
    'QXTK-K2JM-PDOI-RJCN',
    'CDAM-JSJF-TOPX-44IZ',
    'VXQJ-TGZN-76DU-DCWD',
    '6GY4-3WSQ-7IJV-6KL2',
    'K7CR-KYXS-WQIW-W3HZ',
  ],
  issuedAt: '2026-11-02T09:31:12Z',
};

const ADDRESSES = {
  signInAddress: 'ada@example.com',
  contactAddress: 'ada@example.com',
  signInAddressChange: 'allowed',
};

// ---------------------------------------------------------------------------
// The operations
// ---------------------------------------------------------------------------

const NO_CONTENT = (description: string): OperationSuccess => ({ status: 204, description });

export const ACCOUNT_OPERATIONS: readonly AccountOperation[] = [
  // Profile ----------------------------------------------------------------
  {
    id: 'account.profile.get',
    method: 'get',
    path: '/profile',
    tag: 'Profile',
    summary: 'Read the profile',
    description:
      'The profile fields the realm’s profile schema lets the person read, with their values and rules, and the groups the person belongs to.',
    class: 'read',
    permission: 'profile.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    success: { status: 200, schema: 'Profile', description: 'The profile.', etag: true },
    example: { summary: 'A profile with two editable fields', response: PROFILE, etag: ETAG },
  },
  {
    id: 'account.profile.update',
    method: 'patch',
    path: '/profile',
    tag: 'Profile',
    summary: 'Update the profile',
    description:
      'Change the values of fields the person may edit, validated by the realm’s profile schema. It never changes an identifier, the contact address, a verified value or a claim the server sets itself: those fields are refused with `unprocessable_content`.',
    class: 'write',
    permission: 'profile.write',
    freshAuthentication: 'none',
    actChain: 'accepted',
    conditional: true,
    body: { mediaType: 'application/merge-patch+json', schema: 'ProfilePatch', required: true },
    success: { status: 200, schema: 'Profile', description: 'The updated profile.', etag: true },
    example: {
      summary: 'Change the family name',
      ifMatch: ETAG,
      body: { fields: { familyName: 'King' } },
      response: {
        ...PROFILE,
        fields: PROFILE.fields.map((field) =>
          field.name === 'familyName' ? { ...field, value: 'King' } : field
        ),
      },
      etag: NEXT_ETAG,
    },
  },

  // Sign-in methods ----------------------------------------------------------
  {
    id: 'account.signInMethods.get',
    method: 'get',
    path: '/sign-in-methods',
    tag: 'Sign-in methods',
    summary: 'Read the sign-in methods',
    description:
      'Every way the person can sign in: whether a password is set, how many passkeys, whether TOTP is on, how many recovery codes are left, how many accounts are linked, whether there is a contact address, and the factor a fresh authentication must hold.',
    class: 'read',
    permission: 'signInMethods.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    success: { status: 200, schema: 'SignInMethods', description: 'The sign-in methods.' },
    example: {
      summary: 'A password account with a passkey',
      response: {
        password: { set: true, changedAt: '2026-08-14T17:02:45Z' },
        passkeys: { count: 1 },
        totp: { enabled: false },
        recoveryCodes: { remaining: 10 },
        linkedAccounts: { count: 0 },
        hasContactAddress: true,
        freshAuthenticationFactor: 'pop',
      },
    },
  },
  {
    id: 'account.password.change',
    method: 'post',
    path: '/password/change',
    tag: 'Sign-in methods',
    summary: 'Change the password',
    description:
      'Replace the password, with the current one. The realm’s password policy and breach list apply to the new one. A wrong current password counts on the account’s failure ladder. Afterwards the account’s other sessions and refresh-token families end, this session stays, and the "password changed" notice goes out. An account without a password gets `not_found`: setting a first password is not an account API operation.',
    class: 'write',
    permission: 'password.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    body: { mediaType: 'application/json', schema: 'PasswordChangeRequest', required: true },
    success: NO_CONTENT('The password was changed.'),
    codes: ['invalid_current_password', 'not_found', 'weak_password'],
    example: {
      summary: 'Change the password',
      body: {
        currentPassword: 'correct horse battery staple',
        newPassword: 'quiet lantern under a violet harbour',
      },
    },
  },
  {
    id: 'account.passkeys.list',
    method: 'get',
    path: '/passkeys',
    tag: 'Sign-in methods',
    summary: 'List the passkeys',
    description:
      'The passkeys bound to the account, newest first. Adding one is not an account API operation: it runs in the ceremony app on the realm host, whose name is the passkey’s relying-party ID (ADR-020 §1).',
    class: 'read',
    permission: 'passkeys.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    list: {},
    success: { status: 200, schema: 'PasskeyPage', description: 'A page of passkeys.' },
    example: {
      summary: 'The first page',
      query: { limit: 20 },
      response: {
        items: [
          {
            id: PASSKEY_ID,
            nickname: 'Work laptop',
            provider: 'Example Passkey Manager',
            backedUp: true,
            createdAt: '2026-09-30T08:12:00Z',
            lastUsedAt: '2026-11-02T09:20:41Z',
          },
        ],
        nextCursor: null,
      },
    },
  },
  {
    id: 'account.passkeys.get',
    method: 'get',
    path: '/passkeys/{passkeyId}',
    tag: 'Sign-in methods',
    summary: 'Read a passkey',
    description: 'One passkey, with the `ETag` a rename names.',
    class: 'read',
    permission: 'passkeys.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    pathParameters: { passkeyId: 'The passkey’s id.' },
    success: { status: 200, schema: 'Passkey', description: 'The passkey.', etag: true },
    codes: ['not_found'],
    example: {
      summary: 'A synced passkey',
      pathParams: { passkeyId: PASSKEY_ID },
      response: {
        id: PASSKEY_ID,
        nickname: 'Work laptop',
        provider: 'Example Passkey Manager',
        backedUp: true,
        createdAt: '2026-09-30T08:12:00Z',
        lastUsedAt: '2026-11-02T09:20:41Z',
      },
      etag: ETAG,
    },
  },
  {
    id: 'account.passkeys.update',
    method: 'patch',
    path: '/passkeys/{passkeyId}',
    tag: 'Sign-in methods',
    summary: 'Rename a passkey',
    description: 'Change the name the person gave a passkey.',
    class: 'write',
    permission: 'passkeys.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    pathParameters: { passkeyId: 'The passkey’s id.' },
    conditional: true,
    body: { mediaType: 'application/merge-patch+json', schema: 'PasskeyPatch', required: true },
    success: { status: 200, schema: 'Passkey', description: 'The renamed passkey.', etag: true },
    codes: ['not_found'],
    example: {
      summary: 'Rename it',
      pathParams: { passkeyId: PASSKEY_ID },
      ifMatch: ETAG,
      body: { nickname: 'Laptop (work)' },
      response: {
        id: PASSKEY_ID,
        nickname: 'Laptop (work)',
        provider: 'Example Passkey Manager',
        backedUp: true,
        createdAt: '2026-09-30T08:12:00Z',
        lastUsedAt: '2026-11-02T09:20:41Z',
      },
      etag: NEXT_ETAG,
    },
  },
  {
    id: 'account.passkeys.delete',
    method: 'delete',
    path: '/passkeys/{passkeyId}',
    tag: 'Sign-in methods',
    summary: 'Remove a passkey',
    description:
      'Unbind a passkey. The last credential that can sign in, such as the only passkey of a passkey-only account, is refused with `last_credential`; the last second factor the realm requires, with `second_factor_required`. The "passkey removed" notice goes out.',
    class: 'write',
    permission: 'passkeys.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    pathParameters: { passkeyId: 'The passkey’s id.' },
    success: NO_CONTENT('The passkey was removed.'),
    codes: ['not_found', 'last_credential', 'second_factor_required'],
    example: { summary: 'Remove a passkey', pathParams: { passkeyId: PASSKEY_ID } },
  },
  {
    id: 'account.totp.enrollment.create',
    method: 'post',
    path: '/totp/enrollment',
    tag: 'Sign-in methods',
    summary: 'Start an authenticator-app enrolment',
    description:
      'Draw a new TOTP secret and return it once, as text and as an `otpauth://` URI. Nothing is bound until the enrolment is confirmed; a new enrolment replaces one not yet confirmed. For the first second factor of a password-only account QAuth also mails an 8-digit code, unless the sign-in already proved that mailbox. An account that has TOTP gets `conflict`; an unclaimed account cannot enrol. A sign-in that used a recovery code in place of a lost second factor may enrol a new one.',
    class: 'write',
    permission: 'totp.write',
    freshAuthentication: 'strongest-factor-or-recovery-code',
    actChain: 'refused',
    success: { status: 201, schema: 'TotpEnrollment', description: 'The started enrolment.' },
    codes: ['conflict'],
    example: {
      summary: 'Start an enrolment',
      response: {
        secret: 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP',
        otpauthUri:
          'otpauth://totp/Example:ada%40example.com?secret=JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30',
        algorithm: 'SHA1',
        digits: 6,
        period: 30,
        expiresAt: '2026-11-02T09:40:00Z',
        emailCode: 'not_required',
      },
    },
  },
  {
    id: 'account.totp.enrollment.confirm',
    method: 'post',
    path: '/totp/enrollment/confirm',
    tag: 'Sign-in methods',
    summary: 'Confirm an authenticator-app enrolment',
    description:
      'Bind the started enrolment’s secret with a first valid code, and the mailed code when the enrolment asked for one. The first second factor of the account also issues the first set of recovery codes, returned once. The "authenticator app added" notice goes out. Without a started enrolment, or after it lapsed, the answer is `not_found`.',
    class: 'write',
    permission: 'totp.write',
    freshAuthentication: 'strongest-factor-or-recovery-code',
    actChain: 'refused',
    body: { mediaType: 'application/json', schema: 'TotpConfirmRequest', required: true },
    success: {
      status: 200,
      schema: 'TotpConfirmResult',
      description: 'The bound authenticator app.',
    },
    codes: ['invalid_code', 'not_found'],
    example: {
      summary: 'Confirm the first second factor',
      body: { code: '492039' },
      response: { enabledAt: '2026-11-02T09:31:12Z', recoveryCodes: RECOVERY_CODES },
    },
  },
  {
    id: 'account.totp.delete',
    method: 'delete',
    path: '/totp',
    tag: 'Sign-in methods',
    summary: 'Remove the authenticator app',
    description:
      'Unbind TOTP. The last second factor the realm’s policy requires for the account is refused with `second_factor_required`. The "authenticator app removed" notice goes out. An account without TOTP gets `not_found`.',
    class: 'write',
    permission: 'totp.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    success: NO_CONTENT('The authenticator app was removed.'),
    codes: ['not_found', 'second_factor_required'],
    example: { summary: 'Remove TOTP' },
  },
  {
    id: 'account.recoveryCodes.get',
    method: 'get',
    path: '/recovery-codes',
    tag: 'Sign-in methods',
    summary: 'Read the recovery codes’ status',
    description: 'How many recovery codes are left, and when the set was issued. Never the codes.',
    class: 'read',
    permission: 'recoveryCodes.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    success: { status: 200, schema: 'RecoveryCodeStatus', description: 'The status.' },
    example: {
      summary: 'Eight codes left',
      response: { remaining: 8, issuedAt: '2026-09-30T08:12:05Z' },
    },
  },
  {
    id: 'account.recoveryCodes.regenerate',
    method: 'post',
    path: '/recovery-codes/regenerate',
    tag: 'Sign-in methods',
    summary: 'Regenerate the recovery codes',
    description:
      'Issue a new set of ten recovery codes, returned once; the old set stops working. An account without a second factor or a passkey has no recovery codes and gets `conflict`. The "recovery codes regenerated" notice goes out.',
    class: 'write',
    permission: 'recoveryCodes.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    success: { status: 200, schema: 'RecoveryCodeSet', description: 'The new set.' },
    codes: ['conflict'],
    example: { summary: 'A new set', response: RECOVERY_CODES },
  },

  // Sessions -----------------------------------------------------------------
  {
    id: 'account.sessions.list',
    method: 'get',
    path: '/sessions',
    tag: 'Sessions',
    summary: 'List the sessions',
    description:
      'The account’s browser sessions, most recently used first, each with a device label, an approximate location, when it started and when it was last used. `current` marks the one this request’s token came through.',
    class: 'read',
    permission: 'sessions.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    list: {},
    success: { status: 200, schema: 'SessionPage', description: 'A page of sessions.' },
    example: {
      summary: 'Two sessions',
      response: {
        items: [
          {
            id: SESSION_ID,
            current: true,
            createdAt: '2026-11-02T09:20:41Z',
            lastSeenAt: '2026-11-02T09:31:00Z',
            device: LAPTOP,
            location: BERLIN,
          },
          {
            id: OTHER_SESSION_ID,
            current: false,
            createdAt: '2026-10-28T19:44:10Z',
            lastSeenAt: '2026-11-01T21:05:33Z',
            device: PHONE,
          },
        ],
        nextCursor: null,
      },
    },
  },
  {
    id: 'account.sessions.delete',
    method: 'delete',
    path: '/sessions/{sessionId}',
    tag: 'Sessions',
    summary: 'End a session',
    description:
      'End one session: its cookie stops working, its refresh-token families end, and every app it signed in to gets a back-channel logout. It needs no fresh authentication: ending a session only takes access away.',
    class: 'write',
    permission: 'sessions.write',
    freshAuthentication: 'none',
    actChain: 'accepted',
    pathParameters: { sessionId: 'The session’s id.' },
    success: NO_CONTENT('The session ended.'),
    codes: ['not_found'],
    example: { summary: 'End the phone’s session', pathParams: { sessionId: OTHER_SESSION_ID } },
  },
  {
    id: 'account.sessions.endAll',
    method: 'post',
    path: '/sessions/end-all',
    tag: 'Sessions',
    summary: 'Sign out everywhere',
    description:
      'End every session of the account, revoke every refresh-token family, and send a back-channel logout to every app with a session (ADR-017 Decision 8). The session this request’s token came through stays only when `keepCurrent` asks for it.',
    class: 'write',
    permission: 'sessions.write',
    freshAuthentication: 'none',
    actChain: 'accepted',
    body: { mediaType: 'application/json', schema: 'EndAllSessionsRequest', required: false },
    success: NO_CONTENT('Every session ended.'),
    example: { summary: 'Sign out everywhere else', body: { keepCurrent: true } },
  },

  // Security log ---------------------------------------------------------------
  {
    id: 'account.securityLog.list',
    method: 'get',
    path: '/security-log',
    tag: 'Security log',
    summary: 'List the security log',
    description:
      'The account’s security log, newest first: the last 90 days by default, a realm setting. Only the caller’s own entries, and never a raw IP address. A failed sign-in is listed only when its password was right (`second_factor_failed`). `kind` filters by one kind.',
    class: 'read',
    permission: 'securityLog.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    list: { filters: ['kind'] },
    success: { status: 200, schema: 'SecurityLogPage', description: 'A page of the log.' },
    example: {
      summary: 'A sign-in from a new device, and a passkey added',
      query: { limit: 2 },
      response: {
        items: [
          {
            id: ENTRY_ID,
            kind: 'new_device',
            occurredAt: '2026-11-02T09:20:41Z',
            initiator: 'user',
            delegated: false,
            device: LAPTOP,
            location: BERLIN,
            reportable: true,
          },
          {
            id: '019a3e11-4c5d-7e6f-8091-a2b3c4d5e6f7',
            kind: 'credential_added',
            occurredAt: '2026-09-30T08:12:00Z',
            initiator: 'user',
            delegated: false,
            device: LAPTOP,
            credentialType: 'passkey',
            reportable: false,
          },
        ],
        nextCursor: 'eyJ0IjoxNzkxOTcxOTIwMDAwLCJpZCI6IjAxOWEzZTExIn0',
      },
    },
  },
  {
    id: 'account.securityLog.report',
    method: 'post',
    path: '/security-log/{entryId}/report',
    tag: 'Security log',
    summary: 'Report "this wasn’t me"',
    description:
      'Report a sign-in the person does not recognise: the session it started ends with its refresh-token families, and the account’s next sign-in asks for a new password (the `update_password` required action). An entry that is not `reportable` gets `conflict`. It refuses an act-chain token: only the person may say a sign-in was not theirs, and the report changes what the next sign-in asks for.',
    class: 'write',
    permission: 'securityLog.report',
    freshAuthentication: 'none',
    actChain: 'refused',
    pathParameters: { entryId: 'The entry’s id.' },
    success: NO_CONTENT('The report was recorded and the session ended.'),
    codes: ['not_found', 'conflict'],
    example: { summary: 'Report the sign-in from a new device', pathParams: { entryId: ENTRY_ID } },
  },

  // Addresses ----------------------------------------------------------------
  {
    id: 'account.addresses.get',
    method: 'get',
    path: '/addresses',
    tag: 'Addresses',
    summary: 'Read the addresses',
    description:
      'The address the account signs in with, its contact address, and whether the realm lets the person change the sign-in address.',
    class: 'read',
    permission: 'addresses.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    success: { status: 200, schema: 'Addresses', description: 'The addresses.' },
    example: { summary: 'A password account', response: ADDRESSES },
  },
  {
    id: 'account.addressChange.create',
    method: 'post',
    path: '/address-change',
    tag: 'Addresses',
    summary: 'Start an address change',
    description:
      'Start changing the sign-in address, or adding a contact address to an account that signs in without one. An 8-digit code goes to the new address through the capped sender. The answer is the same, in body and timing, whether or not the address belongs to another account; that account’s owner gets the "account already exists" notice. A realm that blocks the change answers `disabled_by_realm`. A new start replaces one not yet confirmed.',
    class: 'write',
    permission: 'addresses.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    body: { mediaType: 'application/json', schema: 'AddressChangeRequest', required: true },
    success: { status: 202, schema: 'AddressChange', description: 'The code was sent.' },
    codes: ['disabled_by_realm'],
    example: {
      summary: 'Change the sign-in address',
      body: { use: 'sign_in', address: 'ada.lovelace@example.org' },
      response: { use: 'sign_in', expiresAt: '2026-11-02T09:41:12Z' },
    },
  },
  {
    id: 'account.addressChange.confirm',
    method: 'post',
    path: '/address-change/confirm',
    tag: 'Addresses',
    summary: 'Confirm an address change',
    description:
      'Complete the change with the code mailed to the new address. A new sign-in address replaces the old one in one transaction; the old address gets the "address changed" notice, and the account’s other sessions and refresh-token families end. Accounts are never matched or linked by address. Without a started change, or after it lapsed, the answer is `not_found`.',
    class: 'write',
    permission: 'addresses.write',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    body: { mediaType: 'application/json', schema: 'AddressChangeConfirmRequest', required: true },
    success: { status: 200, schema: 'Addresses', description: 'The addresses after the change.' },
    codes: ['invalid_code', 'not_found', 'disabled_by_realm'],
    example: {
      summary: 'Confirm with the mailed code',
      body: { code: '40718263' },
      response: {
        ...ADDRESSES,
        signInAddress: 'ada.lovelace@example.org',
        contactAddress: 'ada.lovelace@example.org',
      },
    },
  },

  // Connected apps -------------------------------------------------------------
  {
    id: 'account.consents.list',
    method: 'get',
    path: '/consents',
    tag: 'Connected apps',
    summary: 'List the connected apps',
    description:
      'The person’s active consents, one per app, by when each was first given, newest first. A new grant to the same app keeps its place in the list.',
    class: 'read',
    permission: 'consents.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    list: {},
    success: { status: 200, schema: 'ConsentPage', description: 'A page of consents.' },
    example: {
      summary: 'One connected app',
      response: {
        items: [
          {
            id: CONSENT_ID,
            client_id: 'https://app.example.com/oauth/client.json',
            client_name: 'Example Notes',
            client: EXAMPLE_CLIENT,
            scopes: ['openid', 'profile', 'notes:read'],
            grantedAt: '2026-10-12T15:03:27Z',
          },
        ],
        nextCursor: null,
      },
    },
  },
  {
    id: 'account.consents.delete',
    method: 'delete',
    path: '/consents/{consentId}',
    tag: 'Connected apps',
    summary: 'Disconnect an app',
    description:
      'Revoke one consent, with every refresh token and unredeemed authorization code issued under it. A consent of another account is `not_found`, as one that does not exist. It only takes access away, so it takes an act-chain token: the event names the actor.',
    class: 'write',
    permission: 'consents.write',
    freshAuthentication: 'none',
    actChain: 'accepted',
    pathParameters: { consentId: 'The consent’s id.' },
    success: NO_CONTENT('The consent was revoked.'),
    codes: ['not_found'],
    example: { summary: 'Disconnect an app', pathParams: { consentId: CONSENT_ID } },
  },

  // Account --------------------------------------------------------------------
  {
    id: 'account.deletion.get',
    method: 'get',
    path: '/deletion',
    tag: 'Account',
    summary: 'Preview the deletion',
    description:
      'Whether the realm lets the person delete the account, and what a deletion removes: sessions, consents, sign-in methods, and the developer clients and API keys the account owns.',
    class: 'read',
    permission: 'account.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    success: { status: 200, schema: 'DeletionPreview', description: 'The preview.' },
    example: {
      summary: 'A deletion the realm allows',
      response: { allowed: true, sessions: 2, consents: 1, credentials: 3, clients: 0, apiKeys: 0 },
    },
  },
  {
    id: 'account.deletion.create',
    method: 'post',
    path: '/deletion',
    tag: 'Account',
    summary: 'Delete the account',
    description:
      'Delete the account at once: every row keyed to it, its sessions and refresh-token families, with a back-channel logout to every app for its `sub`. Audit records stay, detached from the account. The "account deleted" notice goes to its address, if any. A realm that turned self-deletion off answers `disabled_by_realm`; then only an admin deletes.',
    class: 'write',
    permission: 'account.delete',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    body: { mediaType: 'application/json', schema: 'DeletionRequest', required: true },
    success: NO_CONTENT('The account is deleted. The token no longer names an account.'),
    codes: ['disabled_by_realm'],
    example: { summary: 'Delete the account', body: { confirmation: DELETION_CONFIRMATION } },
  },

  // Notifications --------------------------------------------------------------
  {
    id: 'account.notificationPreferences.get',
    method: 'get',
    path: '/notification-preferences',
    tag: 'Notifications',
    summary: 'Read the notification preferences',
    description:
      'Every security notice, whether it is mandatory and whether the account receives it, and where notices go. A realm may switch off the notices that are not mandatory (ADR-020 §3).',
    class: 'read',
    permission: 'notificationPreferences.read',
    freshAuthentication: 'none',
    actChain: 'accepted',
    success: {
      status: 200,
      schema: 'NotificationPreferences',
      description: 'The notification preferences.',
    },
    example: {
      summary: 'A realm that kept every notice',
      response: {
        delivery: 'email',
        notices: NOTICE_NAMES.map((notice) => ({
          notice,
          mandatory: NOTICES[notice].mandatory,
          enabled: true,
        })),
      },
    },
  },
];

/** The operation of `id`. */
export function operationNamed(id: string): AccountOperation {
  const operation = ACCOUNT_OPERATIONS.find((candidate) => candidate.id === id);
  if (operation === undefined) throw new Error(`no operation ${id}`);
  return operation;
}

/**
 * Every code an operation may answer, in the registry's order: the ones every
 * operation of its shape answers, and its own.
 *
 * - every operation: `bad_request`, the token guard's 401s and `forbidden`
 *   (a scope, #933), `misdirected_request`, `too_many_requests`,
 *   `internal_error` and `service_unavailable`;
 * - with parameters or a body: `validation_error`; a list: `invalid_cursor`;
 * - with a body: `content_too_large` and `unsupported_media_type`;
 * - an update: `precondition_failed`, `precondition_required` and
 *   `unprocessable_content`;
 * - fresh authentication: `insufficient_user_authentication`;
 * - an act-chain refusal: `delegated_token_refused`.
 */
export function operationCodes(operation: AccountOperation): AccountProblemCodeName[] {
  const codes = new Set<AccountProblemCodeName>([
    'bad_request',
    'unauthorized',
    'invalid_access_token',
    'access_token_expired',
    'forbidden',
    'misdirected_request',
    'too_many_requests',
    'internal_error',
    'service_unavailable',
    ...(operation.codes ?? []),
  ]);
  if (operation.pathParameters || operation.list || operation.body) codes.add('validation_error');
  if (operation.list) codes.add('invalid_cursor');
  if (operation.body) {
    codes.add('content_too_large');
    codes.add('unsupported_media_type');
  }
  if (operation.conditional) {
    codes.add('precondition_failed');
    codes.add('precondition_required');
    codes.add('unprocessable_content');
  }
  if (operation.freshAuthentication !== 'none') codes.add('insufficient_user_authentication');
  if (operation.actChain === 'refused') codes.add('delegated_token_refused');
  return (Object.keys(ACCOUNT_PROBLEM_CODES) as AccountProblemCodeName[]).filter((code) =>
    codes.has(code)
  );
}

/** The error statuses of an operation, ascending, each with its codes. */
export function operationErrors(
  operation: AccountOperation
): Array<[status: number, codes: AccountProblemCodeName[]]> {
  const byStatus = new Map<number, AccountProblemCodeName[]>();
  for (const code of operationCodes(operation)) {
    const { status } = ACCOUNT_PROBLEM_CODES[code];
    byStatus.set(status, [...(byStatus.get(status) ?? []), code]);
  }
  return [...byStatus.entries()].sort(([a], [b]) => a - b);
}
