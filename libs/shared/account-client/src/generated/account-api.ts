/**
 * The typed client of the QAuth Account API v1-rc.0, generated from
 * `apps/docs-site/public/account/v1-rc.0/openapi.json` by
 * `pnpm exec nx run shared-account-client:generate`. Do not edit it by
 * hand: the tests fail while it differs from what the generator writes.
 */

import {
  type AccountClientOptions,
  type CallInit,
  callOperation,
  checkBaseUrl,
} from '../lib/runtime';

/** The version label of the document this client was generated from. */
export const ACCOUNT_API_VERSION = 'v1-rc.0';

/** An RFC 9457 problem details document with a stable `code` and a `trace_id`, and no prose: no `detail`, no `instance`, and field errors as reason codes. */
export interface Problem {
  /** RFC 9457 §3.1.1: `https://docs.qauth.dev/reference/problem-types/#` followed by the type’s slug. Not for branching. */
  type: string;
  /** The problem type’s title (RFC 9457 §3.1.3), the same in every document with this code. Not for branching, and not for a screen. */
  title: string;
  /** The HTTP status, repeated. */
  status: number;
  /** The error. Each error response of an operation lists the codes it may carry (`x-qauth-problem-codes`). A console shows its own text for it, and treats a code it does not know by its HTTP status: a minor release may add codes (ADR-019 Decision 7). */
  code:
    | 'bad_request'
    | 'validation_error'
    | 'invalid_cursor'
    | 'invalid_current_password'
    | 'invalid_code'
    | 'unauthorized'
    | 'access_token_expired'
    | 'invalid_access_token'
    | 'invalid_dpop_proof'
    | 'insufficient_user_authentication'
    | 'forbidden'
    | 'delegated_token_refused'
    | 'disabled_by_realm'
    | 'not_found'
    | 'conflict'
    | 'last_credential'
    | 'second_factor_required'
    | 'precondition_failed'
    | 'content_too_large'
    | 'unsupported_media_type'
    | 'misdirected_request'
    | 'unprocessable_content'
    | 'weak_password'
    | 'precondition_required'
    | 'too_many_requests'
    | 'internal_error'
    | 'service_unavailable'
    | (string & {});
  /** The id the server logged the request under. A console shows it, so an operator can find the failure. */
  trace_id: string;
  /** With `validation_error` and `unprocessable_content`: each refused field and why. */
  errors?: FieldError[];
  /** With `weak_password`: why the new password was refused. */
  reasons?: Array<
    'too_short' | 'too_long' | 'blocklisted' | 'too_weak' | 'breached' | (string & {})
  >;
  /** With `insufficient_user_authentication`: the `max_age` of the challenge (RFC 9470 §3), in seconds. Send the person to the authorization endpoint with it, then repeat the call. */
  max_age?: number;
  /** Never sent: no prose. */
  detail?: never;
  /** Never sent. */
  instance?: never;
}

/** One refused field. */
export interface FieldError {
  /** An RFC 6901 JSON Pointer into the request body, or `/<name>` for a query or path parameter. */
  pointer: string;
  /** Why the field was refused. A console shows its own text, or the message the realm’s profile schema gives the field’s validator. */
  reason:
    | 'required'
    | 'unknown'
    | 'read_only'
    | 'too_short'
    | 'too_long'
    | 'invalid_format'
    | 'not_allowed'
    | (string & {});
}

/** The person’s profile. */
export interface Profile {
  /** The fields the realm’s profile schema lets the person read, in its order. Never an identifier, the contact address or a claim the server sets itself (`sub`, `email`, `email_verified` and the others of ADR-020 fork E). */
  fields: ProfileField[];
  /** The groups the person belongs to, read only. */
  groups: Group[];
}

/** One field of the realm’s user profile schema, with the person’s value. Which fields exist, their types, rules and who may edit them are the realm’s (ADR-020, fork E); the contract shows them as a generic list. */
export interface ProfileField {
  /** The field’s name in the realm’s profile schema, such as `givenName`. */
  name: string;
  /** The field’s label, from the realm’s profile schema. */
  label: string;
  /** The field’s help text, from the realm’s profile schema. */
  help?: string;
  /** How the console asks for the value: free of markup in one line (`text`), an RFC 3339 full date (`date`), or one of `options` (`choice`). A console shows a type it does not know as read-only text. */
  type: 'text' | 'date' | 'choice' | (string & {});
  /** Whether the realm requires a value. */
  required: boolean;
  /** Whether the person may change it. A field only an admin edits, or one the server verified, is not. */
  editable: boolean;
  /** Whether the server verified the value, such as from an upstream provider. */
  verified?: boolean;
  /** The longest value the field accepts. */
  maxLength: number;
  /** For `choice`: the values the field accepts. */
  options?: Array<{
    /** The value stored when the person picks it. */
    value: string;
    /** The option’s label. */
    label: string;
  }>;
  /** The value, or `null` when the field is empty. */
  value: string | null;
}

/** A group the person belongs to. Read only: an admin assigns groups. */
export interface Group {
  /** The group’s id. */
  id: string;
  /** The group’s name, as the realm’s admins set it. */
  name: string;
}

/** A JSON Merge Patch (RFC 7396) of the profile’s values. */
export interface ProfilePatch {
  /** New values by field name. `null` empties a field. A field the person may not edit, or one the schema does not hold, is refused with `unprocessable_content`. */
  fields?: {
    [key: string]: string | null;
  };
}

/** Every way the person can sign in, at a glance. */
export interface SignInMethods {
  password: {
    /** Whether the account has a password. A passkey-only account has none. */
    set: boolean;
    /** When it was last set; `null` without one. */
    changedAt: string | null;
  };
  passkeys: {
    /** How many passkeys are bound. */
    count: number;
  };
  totp: {
    /** Whether an authenticator app (TOTP) is bound. */
    enabled: boolean;
  };
  recoveryCodes: {
    /** How many unused recovery codes are left. */
    remaining: number;
  };
  linkedAccounts: {
    /** How many upstream accounts and wallets are linked. Their lists are the Upstream login and Federation areas’. */
    count: number;
  };
  /** Whether the account has a contact address. Without one, security notices go only to the security log. */
  hasContactAddress: boolean;
  /** The `amr` value a fresh authentication must hold: the account’s strongest bound factor. `pop` with a passkey bound, else `otp` with TOTP, else `pwd` (ADR-017 Decision 8). */
  freshAuthenticationFactor: 'pop' | 'otp' | 'pwd';
}

/** A password change. */
export interface PasswordChangeRequest {
  /** The password the account has now. */
  currentPassword: string;
  /** The new password. The realm’s password policy and breach list apply. */
  newPassword: string;
}

/** A bound passkey. */
export interface Passkey {
  /** The passkey’s id: QAuth’s own, never the WebAuthn credential id. */
  id: string;
  /** The name the person gave it. */
  nickname: string;
  /** The authenticator’s maker, from its AAGUID and the server’s list. Absent when unknown. */
  provider?: string;
  /** Whether the passkey syncs to other devices (the WebAuthn backup state). */
  backedUp: boolean;
  /** When it was added. */
  createdAt: string;
  /** When it last signed in; `null` if never. */
  lastUsedAt: string | null;
}

/** A page of the account’s passkeys, newest first. */
export interface PasskeyPage {
  /** This page’s items, at most `limit`. */
  items: Passkey[];
  /** The cursor of the next page; `null` on the last page. */
  nextCursor: string | null;
}

/** A JSON Merge Patch (RFC 7396) of a passkey: its name. */
export interface PasskeyPatch {
  /** The new name. */
  nickname?: string;
}

/** A started authenticator-app enrolment. Nothing is bound until it is confirmed with a first code. */
export interface TotpEnrollment {
  /** The shared secret, base32 (RFC 4648 §6) without padding: 160 bits. Shown once, for typing by hand; never sent again. */
  secret: string;
  /** The same secret as an `otpauth://totp/` URI with the realm as issuer, for the QR code. Shown once. */
  otpauthUri: string;
  /** Fixed (ADR-020 §3). */
  algorithm: 'SHA1';
  /** Fixed (ADR-020 §3). */
  digits: 6;
  /** Seconds per time step. Fixed (ADR-020 §3). */
  period: 30;
  /** When the enrolment lapses unless confirmed. */
  expiresAt: string;
  /** Whether confirming also needs the 8-digit code QAuth just mailed to the account’s address: the first second factor of a password-only account does, unless the sign-in already proved that mailbox (ADR-017 Decision 8). */
  emailCode: 'required' | 'not_required';
}

/** The confirmation of an authenticator-app enrolment. */
export interface TotpConfirmRequest {
  /** The first code the authenticator app shows. */
  code: string;
  /** The code mailed to the account’s address, when the enrolment asks for one. */
  emailCode?: string;
}

/** A bound authenticator app. `recoveryCodes` is present when it was the account’s first second factor, which issues the first set. */
export interface TotpConfirmResult {
  /** When the authenticator app was bound. */
  enabledAt: string;
  recoveryCodes?: RecoveryCodeSet;
}

/** A new set of recovery codes (ADR-017 Decision 8). */
export interface RecoveryCodeSet {
  /** The ten codes. Shown once: the server keeps only their hashes. */
  codes: string[];
  /** When the set was issued. Every earlier set stopped working then. */
  issuedAt: string;
}

/** The account’s recovery codes, without the codes. */
export interface RecoveryCodeStatus {
  /** How many unused codes are left. */
  remaining: number;
  /** When the current set was issued; `null` without one. */
  issuedAt: string | null;
}

/** A browser session of the account. `location` is absent when unknown. */
export interface Session {
  /** The session’s id: its record’s, never the cookie value. */
  id: string;
  /** Whether the token in this request was issued through this session (its `sid`). */
  current: boolean;
  /** When the session started. */
  createdAt: string;
  /** When it was last used. */
  lastSeenAt: string;
  device: Device;
  location?: Location;
}

/** A page of the account’s sessions, most recently used first. */
export interface SessionPage {
  /** This page’s items, at most `limit`. */
  items: Session[];
  /** The cursor of the next page; `null` on the last page. */
  nextCursor: string | null;
}

/** The device a session or an entry came from. */
export interface Device {
  /** A label from the user agent, such as `Firefox on Linux`. The device declared it. */
  label: string;
}

/** An approximate location from an offline address database. Never the address itself. */
export interface Location {
  /** The country, ISO 3166-1 alpha-2. */
  country: string;
  /** The region, when known. */
  region?: string;
  /** The city, when known. */
  city?: string;
}

/** "Sign out everywhere". */
export interface EndAllSessionsRequest {
  /** Keep the session this request’s token was issued through. Default: end it too. */
  keepCurrent?: boolean;
}

/** What happened. A closed list: a console may branch on every value. Each kind is built from QAuth events (the event types the docs page names). */
export type SecurityLogKind =
  | 'signed_in'
  | 'new_device'
  | 'second_factor_failed'
  | 'session_ended'
  | 'password_changed'
  | 'credential_added'
  | 'credential_removed'
  | 'credential_disabled'
  | 'recovery_code_used'
  | 'recovery_codes_regenerated'
  | 'recovery_codes_failed'
  | 'send_ceiling_reached'
  | 'identifier_changed'
  | 'account_linked'
  | 'account_unlinked'
  | 'consent_granted'
  | 'consent_revoked';

/** One entry of the security log. `device`, `location` and `client` are present when the event recorded them; the raw IP address never is. */
export interface SecurityLogEntry {
  /** The entry’s id: the id of the event it was built from. */
  id: string;
  kind: SecurityLogKind;
  /** When it happened. */
  occurredAt: string;
  /** Who caused it, as CAEP 1.0 §2 names it: the person, an admin, a realm policy, or QAuth itself (a credential disabled after too many attempts). */
  initiator: 'user' | 'admin' | 'policy' | 'system';
  /** Whether it came through an act-chain token: an admin or an agent acting for the person (ADR-019 Decision 7). */
  delegated: boolean;
  device?: Device;
  location?: Location;
  client?: ClientReference;
  /** For `credential_added`, `credential_removed` and `credential_disabled`: which credential. */
  credentialType?: 'password' | 'passkey' | 'totp';
  /** Whether "this wasn’t me" may be reported on it: a sign-in not yet reported. */
  reportable: boolean;
}

/** A page of the security log, newest first. */
export interface SecurityLogPage {
  /** This page’s items, at most `limit`. */
  items: SecurityLogEntry[];
  /** The cursor of the next page; `null` on the last page. */
  nextCursor: string | null;
}

/** The app an entry concerns. */
export interface ClientReference {
  /** The app’s OAuth `client_id`. A console makes it a link only when it is an `https` URL. */
  client_id: string;
  /** The name the app declared about itself. */
  client_name?: string;
}

/** The account’s identifier and contact address. In 1.0 an identifier is an email address (ADR-017). */
export interface Addresses {
  /** The address the account signs in with; `null` for an account with none, such as a passkey-only account. */
  signInAddress: string | null;
  /** Where notices go: the sign-in address, or a contact address added to an account without one; `null` when there is none. */
  contactAddress: string | null;
  /** Whether the realm lets the person change the sign-in address (`blocked`: only an admin can). */
  signInAddressChange: 'allowed' | 'blocked';
}

/** The start of an address change. An 8-digit code goes to the new address. */
export interface AddressChangeRequest {
  /** Which address changes: the one the account signs in with, or the contact address of an account that signs in without one. */
  use: 'sign_in' | 'contact';
  /** The new address. */
  address: string;
}

/** A started address change. The answer is the same whether or not the new address belongs to another account. */
export interface AddressChange {
  /** Which address changes: the one the account signs in with, or the contact address of an account that signs in without one. */
  use: 'sign_in' | 'contact';
  /** When the mailed code lapses. */
  expiresAt: string;
}

/** The confirmation of an address change. */
export interface AddressChangeConfirmRequest {
  /** The code mailed to the new address. */
  code: string;
}

/** A connected app: an active consent the person gave. `client_name` is what the app declared about itself, and a console marks it as declared (ADR-019 Decision 6). A later version may add the verified display data the Interaction API shows for a client, as an optional member. */
export interface Consent {
  /** The consent’s id. */
  id: string;
  /** The app’s OAuth `client_id`, which may be a URL (a Client ID Metadata Document client). A console makes it a link only when it is an `https` URL. */
  client_id: string;
  /** The name the app declared about itself. */
  client_name: string;
  /** The scopes the person granted. */
  scopes: string[];
  /** When the consent was first given. */
  grantedAt: string;
}

/** A page of connected apps, by when each consent was first given, newest first. */
export interface ConsentPage {
  /** This page’s items, at most `limit`. */
  items: Consent[];
  /** The cursor of the next page; `null` on the last page. */
  nextCursor: string | null;
}

/** What deleting the account removes. Audit and event records stay, apart from the account (ADR-018 §3). */
export interface DeletionPreview {
  /** Whether the realm lets the person delete the account. When it does not, only an admin deletes. */
  allowed: boolean;
  /** Sessions that end. */
  sessions: number;
  /** Consents that go, with their refresh tokens. */
  consents: number;
  /** Sign-in methods that go: password, passkeys, TOTP, recovery codes. */
  credentials: number;
  /** Developer clients the account owns, which go with it. */
  clients: number;
  /** API keys of those clients, which stop working. */
  apiKeys: number;
}

/** An account deletion. */
export interface DeletionRequest {
  /** Sent only after the person typed the confirmation the console asked for, in their language. The constant keeps a stray call from deleting. */
  confirmation: 'delete-account';
}

/** The security notices the account receives. Which may be switched off is the realm’s setting (ADR-020 §3); this version reads them. */
export interface NotificationPreferences {
  /** Where notices go: the contact address, or only the security log for an account without one. */
  delivery: 'email' | 'security_log';
  /** Every notice the server sends, in a fixed order. */
  notices: NoticePreference[];
}

/** One security notice. */
export interface NoticePreference {
  /** The notice. A minor release may add notices, such as the new-agent-grant notice of ADR-020 §3; a console shows one it does not know by its `mandatory` and `enabled` alone. */
  notice:
    | 'new_device'
    | 'password_changed'
    | 'credential_disabled'
    | 'credential_added'
    | 'credential_removed'
    | 'recovery_code_used'
    | 'recovery_codes_regenerated'
    | 'recovery_codes_failed'
    | 'send_ceiling_reached'
    | 'second_factor_failed'
    | 'identifier_changed'
    | 'account_deleted'
    | (string & {});
  /** Whether it always goes out: no setting switches it off. */
  mandatory: boolean;
  /** Whether the account receives it now. */
  enabled: boolean;
}

/** Every operation: its method, path, request (path, query and header parameters, body) and response bodies by status. */
export interface Operations {
  'account.profile.get': {
    method: 'GET';
    path: '/account/v1-rc.0/profile';
    request: Record<string, never>;
    responses: {
      200: Profile;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.profile.update': {
    method: 'PATCH';
    path: '/account/v1-rc.0/profile';
    request: { headers: { 'If-Match': string }; body: ProfilePatch };
    responses: {
      200: Profile;
      400: Problem;
      401: Problem;
      403: Problem;
      412: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      422: Problem;
      428: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.signInMethods.get': {
    method: 'GET';
    path: '/account/v1-rc.0/sign-in-methods';
    request: Record<string, never>;
    responses: {
      200: SignInMethods;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.password.change': {
    method: 'POST';
    path: '/account/v1-rc.0/password/change';
    request: { body: PasswordChangeRequest };
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      422: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.passkeys.list': {
    method: 'GET';
    path: '/account/v1-rc.0/passkeys';
    request: { query?: { limit?: number; cursor?: string } };
    responses: {
      200: PasskeyPage;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.passkeys.get': {
    method: 'GET';
    path: '/account/v1-rc.0/passkeys/{passkeyId}';
    request: { path: { passkeyId: string } };
    responses: {
      200: Passkey;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.passkeys.update': {
    method: 'PATCH';
    path: '/account/v1-rc.0/passkeys/{passkeyId}';
    request: { path: { passkeyId: string }; headers: { 'If-Match': string }; body: PasskeyPatch };
    responses: {
      200: Passkey;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      412: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      422: Problem;
      428: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.passkeys.delete': {
    method: 'DELETE';
    path: '/account/v1-rc.0/passkeys/{passkeyId}';
    request: { path: { passkeyId: string } };
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      409: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.totp.enrollment.create': {
    method: 'POST';
    path: '/account/v1-rc.0/totp/enrollment';
    request: Record<string, never>;
    responses: {
      201: TotpEnrollment;
      400: Problem;
      401: Problem;
      403: Problem;
      409: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.totp.enrollment.confirm': {
    method: 'POST';
    path: '/account/v1-rc.0/totp/enrollment/confirm';
    request: { body: TotpConfirmRequest };
    responses: {
      200: TotpConfirmResult;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.totp.delete': {
    method: 'DELETE';
    path: '/account/v1-rc.0/totp';
    request: Record<string, never>;
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      409: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.recoveryCodes.get': {
    method: 'GET';
    path: '/account/v1-rc.0/recovery-codes';
    request: Record<string, never>;
    responses: {
      200: RecoveryCodeStatus;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.recoveryCodes.regenerate': {
    method: 'POST';
    path: '/account/v1-rc.0/recovery-codes/regenerate';
    request: Record<string, never>;
    responses: {
      200: RecoveryCodeSet;
      400: Problem;
      401: Problem;
      403: Problem;
      409: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.sessions.list': {
    method: 'GET';
    path: '/account/v1-rc.0/sessions';
    request: { query?: { limit?: number; cursor?: string } };
    responses: {
      200: SessionPage;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.sessions.delete': {
    method: 'DELETE';
    path: '/account/v1-rc.0/sessions/{sessionId}';
    request: { path: { sessionId: string } };
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.sessions.endAll': {
    method: 'POST';
    path: '/account/v1-rc.0/sessions/end-all';
    request: { body?: EndAllSessionsRequest };
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.securityLog.list': {
    method: 'GET';
    path: '/account/v1-rc.0/security-log';
    request: { query?: { limit?: number; cursor?: string; kind?: SecurityLogKind } };
    responses: {
      200: SecurityLogPage;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.securityLog.report': {
    method: 'POST';
    path: '/account/v1-rc.0/security-log/{entryId}/report';
    request: { path: { entryId: string } };
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      409: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.addresses.get': {
    method: 'GET';
    path: '/account/v1-rc.0/addresses';
    request: Record<string, never>;
    responses: {
      200: Addresses;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.addressChange.create': {
    method: 'POST';
    path: '/account/v1-rc.0/address-change';
    request: { body: AddressChangeRequest };
    responses: {
      202: AddressChange;
      400: Problem;
      401: Problem;
      403: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.addressChange.confirm': {
    method: 'POST';
    path: '/account/v1-rc.0/address-change/confirm';
    request: { body: AddressChangeConfirmRequest };
    responses: {
      200: Addresses;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.consents.list': {
    method: 'GET';
    path: '/account/v1-rc.0/consents';
    request: { query?: { limit?: number; cursor?: string } };
    responses: {
      200: ConsentPage;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.consents.delete': {
    method: 'DELETE';
    path: '/account/v1-rc.0/consents/{consentId}';
    request: { path: { consentId: string } };
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      404: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.deletion.get': {
    method: 'GET';
    path: '/account/v1-rc.0/deletion';
    request: Record<string, never>;
    responses: {
      200: DeletionPreview;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.deletion.create': {
    method: 'POST';
    path: '/account/v1-rc.0/deletion';
    request: { body: DeletionRequest };
    responses: {
      204: undefined;
      400: Problem;
      401: Problem;
      403: Problem;
      413: Problem;
      415: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
  'account.notificationPreferences.get': {
    method: 'GET';
    path: '/account/v1-rc.0/notification-preferences';
    request: Record<string, never>;
    responses: {
      200: NotificationPreferences;
      400: Problem;
      401: Problem;
      403: Problem;
      421: Problem;
      429: Problem;
      500: Problem;
      503: Problem;
    };
  };
}

/** What each operation needs, from the document: parameters, the body's media type, and what it asks of the token. */
export const OPERATIONS = {
  'account.profile.get': {
    method: 'GET',
    path: '/account/v1-rc.0/profile',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.profile.update': {
    method: 'PATCH',
    path: '/account/v1-rc.0/profile',
    pathPatterns: {},
    query: [],
    headers: ['If-Match'],
    bodyMediaType: 'application/merge-patch+json',
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 412, 413, 415, 421, 422, 428, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.signInMethods.get': {
    method: 'GET',
    path: '/account/v1-rc.0/sign-in-methods',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.password.change': {
    method: 'POST',
    path: '/account/v1-rc.0/password/change',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: 'application/json',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    statuses: [204, 400, 401, 403, 404, 413, 415, 421, 422, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.passkeys.list': {
    method: 'GET',
    path: '/account/v1-rc.0/passkeys',
    pathPatterns: {},
    query: ['limit', 'cursor'],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.passkeys.get': {
    method: 'GET',
    path: '/account/v1-rc.0/passkeys/{passkeyId}',
    pathPatterns: { passkeyId: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 404, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.passkeys.update': {
    method: 'PATCH',
    path: '/account/v1-rc.0/passkeys/{passkeyId}',
    pathPatterns: { passkeyId: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
    query: [],
    headers: ['If-Match'],
    bodyMediaType: 'application/merge-patch+json',
    freshAuthentication: 'none',
    actChain: 'refused',
    statuses: [200, 400, 401, 403, 404, 412, 413, 415, 421, 422, 428, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.passkeys.delete': {
    method: 'DELETE',
    path: '/account/v1-rc.0/passkeys/{passkeyId}',
    pathPatterns: { passkeyId: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'strongest-factor-or-recovery-code',
    actChain: 'refused',
    statuses: [204, 400, 401, 403, 404, 409, 421, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.totp.enrollment.create': {
    method: 'POST',
    path: '/account/v1-rc.0/totp/enrollment',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'strongest-factor-or-recovery-code',
    actChain: 'refused',
    statuses: [201, 400, 401, 403, 409, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.totp.enrollment.confirm': {
    method: 'POST',
    path: '/account/v1-rc.0/totp/enrollment/confirm',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: 'application/json',
    freshAuthentication: 'strongest-factor-or-recovery-code',
    actChain: 'refused',
    statuses: [200, 400, 401, 403, 404, 413, 415, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.totp.delete': {
    method: 'DELETE',
    path: '/account/v1-rc.0/totp',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'strongest-factor-or-recovery-code',
    actChain: 'refused',
    statuses: [204, 400, 401, 403, 404, 409, 421, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.recoveryCodes.get': {
    method: 'GET',
    path: '/account/v1-rc.0/recovery-codes',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.recoveryCodes.regenerate': {
    method: 'POST',
    path: '/account/v1-rc.0/recovery-codes/regenerate',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    statuses: [200, 400, 401, 403, 409, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.sessions.list': {
    method: 'GET',
    path: '/account/v1-rc.0/sessions',
    pathPatterns: {},
    query: ['limit', 'cursor'],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.sessions.delete': {
    method: 'DELETE',
    path: '/account/v1-rc.0/sessions/{sessionId}',
    pathPatterns: { sessionId: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [204, 400, 401, 403, 404, 421, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.sessions.endAll': {
    method: 'POST',
    path: '/account/v1-rc.0/sessions/end-all',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: 'application/json',
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [204, 400, 401, 403, 413, 415, 421, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.securityLog.list': {
    method: 'GET',
    path: '/account/v1-rc.0/security-log',
    pathPatterns: {},
    query: ['limit', 'cursor', 'kind'],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.securityLog.report': {
    method: 'POST',
    path: '/account/v1-rc.0/security-log/{entryId}/report',
    pathPatterns: { entryId: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'refused',
    statuses: [204, 400, 401, 403, 404, 409, 421, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.addresses.get': {
    method: 'GET',
    path: '/account/v1-rc.0/addresses',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.addressChange.create': {
    method: 'POST',
    path: '/account/v1-rc.0/address-change',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: 'application/json',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    statuses: [202, 400, 401, 403, 413, 415, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.addressChange.confirm': {
    method: 'POST',
    path: '/account/v1-rc.0/address-change/confirm',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: 'application/json',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    statuses: [200, 400, 401, 403, 404, 413, 415, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.consents.list': {
    method: 'GET',
    path: '/account/v1-rc.0/consents',
    pathPatterns: {},
    query: ['limit', 'cursor'],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.consents.delete': {
    method: 'DELETE',
    path: '/account/v1-rc.0/consents/{consentId}',
    pathPatterns: { consentId: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$' },
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [204, 400, 401, 403, 404, 421, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.deletion.get': {
    method: 'GET',
    path: '/account/v1-rc.0/deletion',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
  'account.deletion.create': {
    method: 'POST',
    path: '/account/v1-rc.0/deletion',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: 'application/json',
    freshAuthentication: 'strongest-factor',
    actChain: 'refused',
    statuses: [204, 400, 401, 403, 413, 415, 421, 429, 500, 503],
    emptyStatuses: [204],
  },
  'account.notificationPreferences.get': {
    method: 'GET',
    path: '/account/v1-rc.0/notification-preferences',
    pathPatterns: {},
    query: [],
    headers: [],
    bodyMediaType: undefined,
    freshAuthentication: 'none',
    actChain: 'accepted',
    statuses: [200, 400, 401, 403, 421, 429, 500, 503],
    emptyStatuses: [],
  },
} as const;

/**
 * A client of the account API, for a backend that holds the person's access
 * token, such as the account console's. `baseUrl` is the auth server's origin
 * for the realm; the token goes to it alone.
 *
 * @throws TypeError when `baseUrl` is not an `https` origin (`http` only on a loopback host)
 */
export function createAccountClient(options: AccountClientOptions) {
  checkBaseUrl(options.baseUrl);
  return {
    /** Read the profile: `account.profile.get`. */
    profileGet: (request: Operations['account.profile.get']['request'] = {}, init?: CallInit) =>
      callOperation<Operations['account.profile.get']>(
        options,
        OPERATIONS['account.profile.get'],
        request,
        init
      ),
    /** Update the profile: `account.profile.update`. */
    profileUpdate: (request: Operations['account.profile.update']['request'], init?: CallInit) =>
      callOperation<Operations['account.profile.update']>(
        options,
        OPERATIONS['account.profile.update'],
        request,
        init
      ),
    /** Read the sign-in methods: `account.signInMethods.get`. */
    signInMethodsGet: (
      request: Operations['account.signInMethods.get']['request'] = {},
      init?: CallInit
    ) =>
      callOperation<Operations['account.signInMethods.get']>(
        options,
        OPERATIONS['account.signInMethods.get'],
        request,
        init
      ),
    /** Change the password: `account.password.change`. */
    passwordChange: (request: Operations['account.password.change']['request'], init?: CallInit) =>
      callOperation<Operations['account.password.change']>(
        options,
        OPERATIONS['account.password.change'],
        request,
        init
      ),
    /** List the passkeys: `account.passkeys.list`. */
    passkeysList: (request: Operations['account.passkeys.list']['request'] = {}, init?: CallInit) =>
      callOperation<Operations['account.passkeys.list']>(
        options,
        OPERATIONS['account.passkeys.list'],
        request,
        init
      ),
    /** Read a passkey: `account.passkeys.get`. */
    passkeysGet: (request: Operations['account.passkeys.get']['request'], init?: CallInit) =>
      callOperation<Operations['account.passkeys.get']>(
        options,
        OPERATIONS['account.passkeys.get'],
        request,
        init
      ),
    /** Rename a passkey: `account.passkeys.update`. */
    passkeysUpdate: (request: Operations['account.passkeys.update']['request'], init?: CallInit) =>
      callOperation<Operations['account.passkeys.update']>(
        options,
        OPERATIONS['account.passkeys.update'],
        request,
        init
      ),
    /** Remove a passkey: `account.passkeys.delete`. */
    passkeysDelete: (request: Operations['account.passkeys.delete']['request'], init?: CallInit) =>
      callOperation<Operations['account.passkeys.delete']>(
        options,
        OPERATIONS['account.passkeys.delete'],
        request,
        init
      ),
    /** Start an authenticator-app enrolment: `account.totp.enrollment.create`. */
    totpEnrollmentCreate: (
      request: Operations['account.totp.enrollment.create']['request'] = {},
      init?: CallInit
    ) =>
      callOperation<Operations['account.totp.enrollment.create']>(
        options,
        OPERATIONS['account.totp.enrollment.create'],
        request,
        init
      ),
    /** Confirm an authenticator-app enrolment: `account.totp.enrollment.confirm`. */
    totpEnrollmentConfirm: (
      request: Operations['account.totp.enrollment.confirm']['request'],
      init?: CallInit
    ) =>
      callOperation<Operations['account.totp.enrollment.confirm']>(
        options,
        OPERATIONS['account.totp.enrollment.confirm'],
        request,
        init
      ),
    /** Remove the authenticator app: `account.totp.delete`. */
    totpDelete: (request: Operations['account.totp.delete']['request'] = {}, init?: CallInit) =>
      callOperation<Operations['account.totp.delete']>(
        options,
        OPERATIONS['account.totp.delete'],
        request,
        init
      ),
    /** Read the recovery codes’ status: `account.recoveryCodes.get`. */
    recoveryCodesGet: (
      request: Operations['account.recoveryCodes.get']['request'] = {},
      init?: CallInit
    ) =>
      callOperation<Operations['account.recoveryCodes.get']>(
        options,
        OPERATIONS['account.recoveryCodes.get'],
        request,
        init
      ),
    /** Regenerate the recovery codes: `account.recoveryCodes.regenerate`. */
    recoveryCodesRegenerate: (
      request: Operations['account.recoveryCodes.regenerate']['request'] = {},
      init?: CallInit
    ) =>
      callOperation<Operations['account.recoveryCodes.regenerate']>(
        options,
        OPERATIONS['account.recoveryCodes.regenerate'],
        request,
        init
      ),
    /** List the sessions: `account.sessions.list`. */
    sessionsList: (request: Operations['account.sessions.list']['request'] = {}, init?: CallInit) =>
      callOperation<Operations['account.sessions.list']>(
        options,
        OPERATIONS['account.sessions.list'],
        request,
        init
      ),
    /** End a session: `account.sessions.delete`. */
    sessionsDelete: (request: Operations['account.sessions.delete']['request'], init?: CallInit) =>
      callOperation<Operations['account.sessions.delete']>(
        options,
        OPERATIONS['account.sessions.delete'],
        request,
        init
      ),
    /** Sign out everywhere: `account.sessions.endAll`. */
    sessionsEndAll: (
      request: Operations['account.sessions.endAll']['request'] = {},
      init?: CallInit
    ) =>
      callOperation<Operations['account.sessions.endAll']>(
        options,
        OPERATIONS['account.sessions.endAll'],
        request,
        init
      ),
    /** List the security log: `account.securityLog.list`. */
    securityLogList: (
      request: Operations['account.securityLog.list']['request'] = {},
      init?: CallInit
    ) =>
      callOperation<Operations['account.securityLog.list']>(
        options,
        OPERATIONS['account.securityLog.list'],
        request,
        init
      ),
    /** Report "this wasn’t me": `account.securityLog.report`. */
    securityLogReport: (
      request: Operations['account.securityLog.report']['request'],
      init?: CallInit
    ) =>
      callOperation<Operations['account.securityLog.report']>(
        options,
        OPERATIONS['account.securityLog.report'],
        request,
        init
      ),
    /** Read the addresses: `account.addresses.get`. */
    addressesGet: (request: Operations['account.addresses.get']['request'] = {}, init?: CallInit) =>
      callOperation<Operations['account.addresses.get']>(
        options,
        OPERATIONS['account.addresses.get'],
        request,
        init
      ),
    /** Start an address change: `account.addressChange.create`. */
    addressChangeCreate: (
      request: Operations['account.addressChange.create']['request'],
      init?: CallInit
    ) =>
      callOperation<Operations['account.addressChange.create']>(
        options,
        OPERATIONS['account.addressChange.create'],
        request,
        init
      ),
    /** Confirm an address change: `account.addressChange.confirm`. */
    addressChangeConfirm: (
      request: Operations['account.addressChange.confirm']['request'],
      init?: CallInit
    ) =>
      callOperation<Operations['account.addressChange.confirm']>(
        options,
        OPERATIONS['account.addressChange.confirm'],
        request,
        init
      ),
    /** List the connected apps: `account.consents.list`. */
    consentsList: (request: Operations['account.consents.list']['request'] = {}, init?: CallInit) =>
      callOperation<Operations['account.consents.list']>(
        options,
        OPERATIONS['account.consents.list'],
        request,
        init
      ),
    /** Disconnect an app: `account.consents.delete`. */
    consentsDelete: (request: Operations['account.consents.delete']['request'], init?: CallInit) =>
      callOperation<Operations['account.consents.delete']>(
        options,
        OPERATIONS['account.consents.delete'],
        request,
        init
      ),
    /** Preview the deletion: `account.deletion.get`. */
    deletionGet: (request: Operations['account.deletion.get']['request'] = {}, init?: CallInit) =>
      callOperation<Operations['account.deletion.get']>(
        options,
        OPERATIONS['account.deletion.get'],
        request,
        init
      ),
    /** Delete the account: `account.deletion.create`. */
    deletionCreate: (request: Operations['account.deletion.create']['request'], init?: CallInit) =>
      callOperation<Operations['account.deletion.create']>(
        options,
        OPERATIONS['account.deletion.create'],
        request,
        init
      ),
    /** Read the notification preferences: `account.notificationPreferences.get`. */
    notificationPreferencesGet: (
      request: Operations['account.notificationPreferences.get']['request'] = {},
      init?: CallInit
    ) =>
      callOperation<Operations['account.notificationPreferences.get']>(
        options,
        OPERATIONS['account.notificationPreferences.get'],
        request,
        init
      ),
  };
}

export type AccountClient = ReturnType<typeof createAccountClient>;
