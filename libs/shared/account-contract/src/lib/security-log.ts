/**
 * The security log's entry kinds (ADR-020 §3, ADR-018 §3, #689): a closed
 * list, each kind built from QAuth events (#456) through an allow list.
 *
 * The security log shows a person the last 90 days of their own sign-ins, new
 * devices and security changes. It is read from the event store, never from
 * a log of its own: each kind names the event types its entries come from, by
 * their registry name (`user.signed_in` is `urn:qauth:event:user.signed_in:v1-rc.0`).
 *
 * A source is `registered` when the event registry (`@qauth-labs/shared-events`)
 * holds the type today, or `planned` when the feature that will emit it has
 * not shipped: the registry adds a type in the pull request of the feature
 * that emits it, and the events page lists only what QAuth emits. A planned
 * source names that feature's issue. The auth server's
 * `account-contract.test.ts` keeps the list matched to the registry both ways
 * (shared libraries are leaves, so this one cannot import the registry):
 *
 * - every registered source is a registered type whose subject is a user;
 * - every planned source is not registered yet, so the pull request that
 *   registers it must mark it registered here, in the same change;
 * - every registered type whose subject is a user is either a source here or
 *   in {@link NOT_IN_SECURITY_LOG}, with the reason it is left out.
 *
 * The list is closed: the `kind` of an entry is an `enum`, and a console may
 * branch on every value. Adding a kind is a breaking change of the account
 * API (it raises the release candidate before 1.0.0), so the list covers
 * every kind behind the notices #693 sends, which an account with no contact
 * address sees only here (ADR-020 §3, Emails).
 */

/**
 * Where a kind's entries come from: an event type, by its registry name, and,
 * when only some of its events belong to the kind, which ones (`only`).
 */
export type SecurityLogSource =
  | { readonly event: string; readonly status: 'registered'; readonly only?: string }
  | {
      readonly event: string;
      readonly status: 'planned';
      readonly issue: number;
      readonly only?: string;
    };

export interface SecurityLogKind {
  /** What the entry tells the person, in one sentence. */
  readonly description: string;
  /** The event types its entries are built from. */
  readonly sources: readonly SecurityLogSource[];
  /** Whether "this wasn't me" may be reported on it: a sign-in that started a session. */
  readonly reportable: boolean;
}

const registered = (event: string, only?: string): SecurityLogSource => ({
  event,
  status: 'registered',
  ...(only === undefined ? {} : { only }),
});
const planned = (event: string, issue: number): SecurityLogSource => ({
  event,
  status: 'planned',
  issue,
});

/** Every kind, in the order the console's filter lists them. */
export const SECURITY_LOG_KINDS = {
  signed_in: {
    description: 'The person signed in.',
    sources: [registered('user.signed_in')],
    reportable: true,
  },
  new_device: {
    description:
      'The person signed in from a device QAuth had not seen for the account (the device recognition of #689).',
    sources: [planned('user.new_device_seen', 689)],
    reportable: true,
  },
  second_factor_failed: {
    description:
      'A sign-in gave the right password and then a wrong second factor. Only these failed sign-ins are shown: a log of every failed sign-in would tell an attacker which guesses reached the account.',
    sources: [
      registered(
        'user.sign_in_failed',
        'a refused second-factor step after an accepted password, whose `method` is the second factor’s (TOTP from F2c); never a refused identifier or password'
      ),
    ],
    reportable: false,
  },
  session_ended: {
    description:
      'A session ended: a sign-out, one session ended from the console, or "sign out everywhere".',
    sources: [registered('user.signed_out')],
    reportable: false,
  },
  password_changed: {
    description: 'The account’s password was changed.',
    sources: [registered('user.password_reset'), planned('user.password_changed', 685)],
    reportable: false,
  },
  credential_added: {
    description: 'A passkey or an authenticator app (TOTP) was added to the account.',
    sources: [planned('user.credential_added', 686)],
    reportable: false,
  },
  credential_removed: {
    description: 'A passkey or an authenticator app (TOTP) was removed from the account.',
    sources: [planned('user.credential_removed', 686)],
    reportable: false,
  },
  credential_disabled: {
    description:
      'The password or the authenticator app was disabled after too many wrong attempts (ADR-017 Decision 7).',
    sources: [planned('user.credential_disabled', 693)],
    reportable: false,
  },
  recovery_code_used: {
    description: 'A recovery code was used in place of a second factor.',
    sources: [planned('user.recovery_code_used', 649)],
    reportable: false,
  },
  recovery_codes_regenerated: {
    description: 'A new set of recovery codes replaced the old one.',
    sources: [planned('user.recovery_codes_regenerated', 687)],
    reportable: false,
  },
  recovery_codes_failed: {
    description: 'Recovery codes were tried and refused 100 times (ADR-017 Decision 7).',
    sources: [planned('user.recovery_codes_failed', 649)],
    reportable: false,
  },
  send_ceiling_reached: {
    description:
      'Codes were requested for the account’s address past the per-address send ceiling, and a notice with a reset pass went to it (ADR-017 Decision 7).',
    sources: [planned('user.send_ceiling_reached', 637)],
    reportable: false,
  },
  identifier_changed: {
    description: 'The address the account signs in with, or its contact address, changed.',
    sources: [planned('user.identifier_changed', 690)],
    reportable: false,
  },
  account_linked: {
    description: 'A wallet or an upstream account was linked to the account.',
    sources: [registered('wallet.linked'), planned('user.upstream_linked', 670)],
    reportable: false,
  },
  account_unlinked: {
    description: 'A wallet or an upstream account was unlinked from the account.',
    sources: [planned('user.upstream_unlinked', 670)],
    reportable: false,
  },
  consent_granted: {
    description: 'The person let an app access the account.',
    sources: [registered('consent.granted')],
    reportable: false,
  },
  consent_revoked: {
    description: 'An app’s access to the account was withdrawn.',
    sources: [registered('consent.revoked')],
    reportable: false,
  },
} as const satisfies Record<string, SecurityLogKind>;

export type SecurityLogKindName = keyof typeof SECURITY_LOG_KINDS;

export const SECURITY_LOG_KIND_NAMES = Object.keys(SECURITY_LOG_KINDS) as SecurityLogKindName[];

/**
 * The registered event types whose subject is a user that the security log
 * leaves out, each with the reason. A test fails when such a type is neither a
 * source above nor listed here, so a new user event is a decision, not an
 * omission.
 */
export const NOT_IN_SECURITY_LOG: Readonly<Record<string, string>> = {
  'user.sign_in_step_passed':
    'One step of a sign-in; the sign-in itself is the entry (`signed_in`).',
  'user.sign_out_failed': 'A refused sign-out changes nothing on the account.',
  'user.password_breach_check_failed':
    'A breach-list check QAuth could not make changes nothing on the account; the operator watches it.',
  'user.client_session_ended':
    'The notice to one app that a session ended, for back-channel logout; the end of the session is the entry.',
  'user.registered': 'The account’s creation, older than the log for most accounts.',
  'user.disabled':
    'An operator’s switch, recorded in the admin events; a disabled account cannot read its log.',
  'user.enabled': 'An operator’s switch, recorded in the admin events.',
  'authorization.completed': 'An app’s authorization request; the sign-in behind it is the entry.',
  'authorization.failed': 'A refused authorization request changes nothing on the account.',
  'step_up.required': 'A request for a fresh sign-in; the sign-in that follows is the entry.',
  'step_up.elevated': 'A fresh sign-in; the sign-in itself is the entry (`signed_in`).',
  'consent.administrative':
    'An operator-flagged first-party app that needs no consent (ADR-017 Decision 9); no consent was stored.',
  'consent.denied': 'A consent the person did not give changes nothing on the account.',
  'token.issued': 'One token among many; the sign-in and the consent are the entries.',
  'token.request_failed': 'A refused token request changes nothing on the account.',
  'token.family_revoked':
    'A refresh-token family revoked on reuse or with a session; the session or consent entry covers it.',
  'token.revoked': 'An app revoking its own token; the consent entry covers what the person did.',
  'token.introspected': 'A resource server checking a token: no change.',
  'token.introspection_failed': 'A refused introspection: no change.',
  'userinfo.served': 'An app reading the person’s claims: no change.',
  'userinfo.request_failed': 'A refused userinfo request: no change.',
  'wallet.link_failed': 'A link that did not happen changes nothing on the account.',
  'interaction.created': 'A sign-in page opened; the sign-in itself is the entry.',
  'interaction.answered': 'One answer within a sign-in; the sign-in itself is the entry.',
  'interaction.cancelled': 'A sign-in the person abandoned changes nothing on the account.',
  'interaction.expired': 'A sign-in that timed out changes nothing on the account.',
  'request.csrf_rejected': 'A refused request changes nothing on the account.',
};

/** How long the log keeps an entry by default; a realm setting (#689). */
export const SECURITY_LOG_DEFAULT_RETENTION_DAYS = 90;
