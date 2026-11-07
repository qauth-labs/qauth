import { z } from 'zod';

import { defineEventType } from '../definition';
import { extensibleEnum } from '../envelope';
import {
  CAEP_CREDENTIAL_CHANGE,
  CAEP_SESSION_REVOKED,
  RISC_ACCOUNT_DISABLED,
  RISC_ACCOUNT_ENABLED,
} from '../ssf-mapping';
import {
  FIRST_RELEASE,
  identifierHmac,
  reason,
  recordId,
  signInMethod,
  stepName,
  verifierProfile,
} from './fields';

/**
 * A person's own account activity: sign-in, sign-out and registration; and an
 * operator's switch of the account.
 */

export const userSignedIn = defineEventType({
  name: 'user.signed_in',
  version: 1,
  rc: 0,
  description:
    'A person signed in: the credential checked out and QAuth started a browser session or issued tokens.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    method: signInMethod(),
    verifierProfile: verifierProfile().optional(),
  }),
});

export const userSignInFailed = defineEventType({
  name: 'user.sign_in_failed',
  version: 1,
  rc: 0,
  description:
    'A sign-in was refused: an unknown identifier, a wrong credential, a locked or disabled account.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    method: signInMethod(),
    reason: reason(),
    identifierHmac: identifierHmac().optional(),
    verifierProfile: verifierProfile().optional(),
  }),
});

/**
 * One accepted step of a sign-in, from the sign-in engine (#614): every
 * transport that runs the engine records it, the Interaction API and the
 * FiPA endpoint alike. A refused or ended step is `user.sign_in_failed`.
 */
export const userSignInStepPassed = defineEventType({
  name: 'user.sign_in_step_passed',
  version: 1,
  rc: 0,
  description:
    'The sign-in engine accepted an answer to one step of a sign-in: the identifier, a solved bot challenge, or a factor that proved who the person is. A refused answer is user.sign_in_failed; the session or the tokens the sign-in leads to are user.signed_in.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    step: stepName('The step whose answer was accepted.'),
    identifierHmac: identifierHmac().optional(),
  }),
});

/**
 * A breach-list check of a password that could not be made (#635, ADR-020
 * §3): the realm's local list was not loaded, or the range lookup failed or
 * was refused. A failed check never blocks a sign-in, a password update or a
 * registration, so the password was taken as not listed; this event is the
 * record of that.
 */
export const userPasswordBreachCheckFailed = defineEventType({
  name: 'user.password_breach_check_failed',
  version: 1,
  rc: 0,
  description:
    "QAuth could not check a password against the realm's breach list (the local list was not loaded, or the range lookup failed or was refused) and took it as not listed: a failed check never blocks a sign-in, a password update or a registration. The subject is the account whose password it was, when one exists.",
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    step: stepName(
      'The sign-in step whose password was checked: the password, or a new password. Absent for a registration through `POST /auth/register`.'
    ).optional(),
    reason: reason(
      'Why the check failed: `not_configured`, `list_not_loaded`, `lookup_blocked`, `lookup_failed`, `bad_response` or `unavailable`. The set may grow in a minor release.'
    ),
  }),
});

export const userSignedOut = defineEventType({
  name: 'user.signed_out',
  version: 1,
  rc: 0,
  description:
    'A person signed out, and QAuth ended their browser sessions: the one session the relying party named at the end-session endpoint (OpenID Connect RP-Initiated Logout 1.0), one session the person ended on the hosted account page, or every session of the user at `POST /auth/logout` or at "sign out everywhere" on the hosted account page.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    sid: recordId(
      'The browser session this sign-out ended, when it ended one: the `sid` its ID tokens carry (#549). Absent when the sign-out ended every session of the user, as `POST /auth/logout` and "sign out everywhere" do.'
    ).optional(),
  }),
  security: true,
  ssf: { event: CAEP_SESSION_REVOKED, session: 'sid' },
});

/**
 * The back-channel logout notice of one client and one session (OpenID
 * Connect Back-Channel Logout 1.0, issue #624): the session revocation writes
 * it in its own transaction, so the notice commits with the end, and the
 * delivery role sends the client its logout token from it.
 */
export const userClientSessionEnded = defineEventType({
  name: 'user.client_session_ended',
  version: 1,
  rc: 0,
  description:
    'A browser session ended that had served a client with a registered `backchannel_logout_uri`, and QAuth queued that client a logout token (OpenID Connect Back-Channel Logout 1.0). One event per client and session, written in the transaction that ended the session, whatever ended it: a sign-out, an admin, a reset, a retired key, the browser limit or the session lapsing. `client` is the client to notify.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    sid: recordId('The session that ended: the `sid` its ID tokens and the logout token carry.'),
    reason: reason(),
  }),
  security: true,
  ssf: 'none',
  ssfNote:
    'The end of a session is user.signed_out, sent as CAEP 1.0 `session-revoked`. This event is the per-client notice of OpenID Connect Back-Channel Logout 1.0, delivered as a logout token to the client, not as a SET.',
});

export const userSignOutFailed = defineEventType({
  name: 'user.sign_out_failed',
  version: 1,
  rc: 0,
  description: 'A sign-out request was refused or could not complete.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    reason: reason(),
  }),
});

export const userRegistered = defineEventType({
  name: 'user.registered',
  version: 1,
  rc: 0,
  description: 'A person created an account.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    method: signInMethod(),
  }),
});

export const userRegistrationFailed = defineEventType({
  name: 'user.registration_failed',
  version: 1,
  rc: 0,
  description: 'An account could not be created, for example because the address is in use.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  data: z.strictObject({
    reason: reason(),
    identifierHmac: identifierHmac().optional(),
  }),
});

/**
 * The owner's password reset (#642; ADR-017 Decision 8), recorded in the
 * transaction that replaced the password: an emailed code proved the
 * mailbox, and any other authenticator the account holds proved it too.
 */
export const userPasswordReset = defineEventType({
  name: 'user.password_reset',
  version: 1,
  rc: 0,
  description:
    "A person reset their account's password: an emailed code proved the mailbox, every other authenticator the account holds proved it too, and a new password replaced the old one. Every refresh token and browser session the account held ends with it, and so does every sign-in in progress for it.",
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: {
    event: CAEP_CREDENTIAL_CHANGE,
    members: {
      credential_type: { value: 'password' },
      change_type: { value: 'update' },
    },
  },
});

/**
 * A recovery code used at sign-in (#649; ADR-017 Decision 8), recorded in
 * the transaction that took the code, so a used code always has its event.
 */
export const userRecoveryCodeUsed = defineEventType({
  name: 'user.recovery_code_used',
  version: 1,
  rc: 0,
  description:
    'A person used one of their recovery codes in place of a second factor on the hosted pages: after the password to sign in, or after the code mailed to their address to reset the password. A code works once; it adds no `amr` value to the sign-in, and the person is told by email.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    // A set holds 10 codes (ADR-017 Decision 8): no payload says more are left.
    remaining: z
      .int()
      .min(0)
      .max(10)
      .describe('How many of the set are left unused after this one: 0 to 10.'),
  }),
  security: true,
  ssf: 'none',
  ssfNote:
    'CAEP 1.0 has no event for a sign-in that used a fallback authenticator, and `credential-change` is for a credential created, revoked, updated or deleted: a used code is spent, not changed.',
});

/**
 * The recovery codes' hard ceiling (#649; ADR-017 Decision 7): wrong codes
 * reached 100 in a row for an account, counted per account across every
 * transaction and IP. Recorded at most once a day per account, with the
 * user's notice and the operator's alert.
 */
export const userRecoveryCodesFailed = defineEventType({
  name: 'user.recovery_codes_failed',
  version: 1,
  rc: 0,
  description:
    'Wrong recovery codes reached 100 in a row for an account, each after a first proof: the right password at sign-in, or the code mailed to the account’s address in a password reset. Someone who holds one of those is guessing its codes. Every further try waits up to 15 minutes; the person is told by email and the operator alerted. Recorded at most once a day per account.',
  category: 'user',
  severity: 'critical',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: 'none',
  ssfNote:
    'Neither CAEP 1.0 nor RISC 1.0 has an event for failed attempts at an account’s credential: the account is not disabled and no credential changed.',
});

/**
 * An operator's switch of an account (#748). Until the admin API has user
 * operations (#681), the `db:disable-user` operator tool is the one path that
 * emits these, in the transaction of the change.
 */

export const userDisabled = defineEventType({
  name: 'user.disabled',
  version: 1,
  rc: 0,
  description:
    'An operator disabled an account: it can no longer sign in or obtain tokens, and every browser session and token issued to it before now stays refused, also after it is enabled again.',
  category: 'admin',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: { event: RISC_ACCOUNT_DISABLED },
  ssfNote:
    'Sent without `reason`: RISC 1.0 names only `hijacking` and `bulk-account`, and QAuth records no reason for the switch.',
});

export const userEnabled = defineEventType({
  name: 'user.enabled',
  version: 1,
  rc: 0,
  description:
    'An operator enabled a disabled account again. The person signs in again: what was issued before the account was disabled stays refused.',
  category: 'admin',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: { event: RISC_ACCOUNT_ENABLED },
});

/**
 * Account linking (#670; ADR-020 §3, NIST SP 800-63C-4 §5.4): an upstream
 * identity joins an existing account only once the person signed in to that
 * account with its own factors, in the interaction in which the provider
 * proved the identity, and leaves it only through a fresh sign-in. Recorded
 * in the transaction of the change.
 */

/** The upstream identity provider an identity is of: its AuthMethod `type`. */
const upstreamProviderType = () =>
  z
    .string()
    .min(1)
    .max(63)
    .regex(/^[a-z][a-z0-9_]{0,62}$/)
    .describe('The upstream identity provider, by its type, such as `oidc_corp`.');

export const userUpstreamLinked = defineEventType({
  name: 'user.upstream_linked',
  version: 1,
  rc: 0,
  description:
    'A person linked an upstream identity to their account: the provider proved the identity, and the person then signed in to the account with its own factors and its MFA policy, in the same browser and the same interaction. The account can sign in through the provider from now on. The person is told by email.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    provider: upstreamProviderType(),
    credentialId: recordId('The id of the account credential the identity was linked as.'),
  }),
  security: true,
  ssf: 'none',
  ssfNote:
    'CAEP 1.0 `credential-change` names its credential by a type it lists (a password, a FIDO key, a verifiable credential), and none is an identity at another provider; no type is agreed with receivers yet.',
});

export const userUpstreamUnlinked = defineEventType({
  name: 'user.upstream_unlinked',
  version: 1,
  rc: 0,
  description:
    'A person removed an upstream identity from their account through the account API, after a fresh sign-in. The account no longer signs in through that provider; the attributes the provider gave stay. The person is told by email.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    provider: upstreamProviderType(),
    credentialId: recordId('The id of the account credential that was removed.'),
  }),
  security: true,
  ssf: 'none',
  ssfNote:
    'CAEP 1.0 `credential-change` names its credential by a type it lists (a password, a FIDO key, a verifiable credential), and none is an identity at another provider; no type is agreed with receivers yet.',
});

export const userUpstreamLinkFailed = defineEventType({
  name: 'user.upstream_link_failed',
  version: 1,
  rc: 0,
  description:
    'An upstream identity could not be linked. `reason`: `already_linked`, another account holds the identity; `provider_linked`, the account already holds an identity of that provider; `account_unavailable`, the account signed in to is gone or disabled. Nothing was linked. The subject is the account the person signed in to, or the one that holds the identity when nobody has signed in yet.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    provider: upstreamProviderType(),
    reason: reason(),
  }),
  security: true,
  ssf: 'none',
  ssfNote: 'Nothing changed: no credential was created, changed or deleted.',
});

/**
 * A person's own changes to the ways into their account (#844; ADR-020 §3):
 * a password changed, a passkey or an authenticator app bound or removed, a
 * passkey renamed, a new set of recovery codes. Each is recorded in the
 * transaction of the change, but for the recovery codes, whose set is
 * replaced by the store's own write and recorded right after it.
 */

/** The kinds of credential a person binds or removes beside the password. */
export const OWN_CREDENTIAL_TYPES = ['passkey', 'totp'] as const;

const ownCredentialType = () =>
  extensibleEnum(OWN_CREDENTIAL_TYPES).describe(
    '`passkey`: a WebAuthn passkey. `totp`: an authenticator app (TOTP). The set may grow in a minor release.'
  );

export const userPasswordChanged = defineEventType({
  name: 'user.password_changed',
  version: 1,
  rc: 0,
  description:
    "A person changed their account's password with the current one, after a fresh sign-in with the account's strongest factor, on the hosted account page. The new password met the realm's password policy. Every other browser session and every refresh token of the account ended; the session the change was made in stays. The person is told by email.",
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: {
    event: CAEP_CREDENTIAL_CHANGE,
    members: {
      credential_type: { value: 'password' },
      change_type: { value: 'update' },
    },
  },
});

export const userCredentialAdded = defineEventType({
  name: 'user.credential_added',
  version: 1,
  rc: 0,
  description:
    'A passkey or an authenticator app (TOTP) was bound to a person’s account, in a step of the hosted pages the person answered: after a sign-in that offered or asked for it, in a recovery that replaced a lost passkey, or from the hosted account page after a fresh sign-in. A passkey an account was registered with is recorded by the registration (`user.registered`).',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    type: ownCredentialType(),
    credentialId: recordId('The id of the account credential that was bound.'),
  }),
  security: true,
  ssf: 'none',
  ssfNote:
    'CAEP 1.0 `credential-change` tells a platform passkey (`fido2-platform`) from a roaming one (`fido2-roaming`), and QAuth does not record which kind of authenticator created a passkey.',
});

export const userCredentialRemoved = defineEventType({
  name: 'user.credential_removed',
  version: 1,
  rc: 0,
  description:
    'A person removed a passkey or their authenticator app (TOTP) from their account on the hosted account page, after a fresh sign-in with the account’s strongest factor or with a recovery code in place of a lost one. The account no longer signs in with it.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    type: ownCredentialType(),
    credentialId: recordId('The id of the account credential that was removed.'),
  }),
  security: true,
  ssf: 'none',
  ssfNote:
    'CAEP 1.0 `credential-change` tells a platform passkey (`fido2-platform`) from a roaming one (`fido2-roaming`), and QAuth does not record which kind of authenticator created a passkey.',
});

export const userPasskeyRenamed = defineEventType({
  name: 'user.passkey_renamed',
  version: 1,
  rc: 0,
  description:
    'A person changed the name they gave one of their passkeys, on the hosted account page. A name is no credential: the passkey signs in as before.',
  category: 'user',
  severity: 'info',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({
    credentialId: recordId('The id of the passkey’s account credential.'),
  }),
});

export const userRecoveryCodesRegenerated = defineEventType({
  name: 'user.recovery_codes_regenerated',
  version: 1,
  rc: 0,
  description:
    'A person issued a new set of recovery codes on the hosted account page, after a fresh sign-in with the account’s strongest factor: every code of the old set stopped working, and the new codes were shown once. The person is told by email.',
  category: 'user',
  severity: 'warning',
  since: FIRST_RELEASE,
  subject: 'user',
  data: z.strictObject({}),
  security: true,
  ssf: 'none',
  ssfNote:
    'CAEP 1.0 `credential-change` lists no credential type for a set of recovery codes, and none is agreed with receivers yet.',
});

export const USER_EVENT_TYPES = [
  userSignedIn,
  userSignInFailed,
  userSignInStepPassed,
  userPasswordBreachCheckFailed,
  userSignedOut,
  userClientSessionEnded,
  userSignOutFailed,
  userRegistered,
  userRegistrationFailed,
  userPasswordReset,
  userRecoveryCodeUsed,
  userRecoveryCodesFailed,
  userDisabled,
  userEnabled,
  userUpstreamLinked,
  userUpstreamUnlinked,
  userUpstreamLinkFailed,
  userPasswordChanged,
  userCredentialAdded,
  userCredentialRemoved,
  userPasskeyRenamed,
  userRecoveryCodesRegenerated,
] as const;
