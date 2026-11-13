import {
  buildPasswordCredentialData,
  normalisePasskeyNickname,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  presentedPasswordFor,
  WEBAUTHN_PROVIDER_TYPE,
  webauthnCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import type { BrowserSession, ListedSession } from '@qauth-labs/fastify-plugin-sessions';
import {
  NO_SECOND_FACTOR_POLICY,
  type PasswordAttempt,
  SignInStoreUnavailableError,
  TOTP_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import {
  type AccountFactor,
  FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
  holdsNewFactor,
  isFreshSignIn,
  provedOnlyThroughNew,
  requiredFactorOf,
} from './account-operation-guard';
import { accountPoliciesOf } from './account-policies';
import { endBrowserSession, endBrowserSessions } from './browser-session';
import type { EngineMailer } from './engine-mail';
import type { InteractionEngines } from './interaction-engines';
import { ACCOUNT_PAGES_ENGINE_CLIENT_ID } from './interaction-record';
import { isNewCredential, passkeyAuthenticatorOf } from './new-factors';
import { ladderEndUserIp } from './password-attempts';
import { recordPasswordChange } from './password-reset';
import { requestRealm } from './request-realm';
import { csrfTokensEqual, generateCsrfToken } from './session-cookie';
import { readSessionSideRecord, writeSessionSideRecord } from './session-side-record';
import { type LinkedAccount, pageLinkedAccounts, signsInNow } from './upstream-links';
import { upstreamProviderCatalog } from './upstream-providers';
import { emitUserEvent } from './user-events';

/**
 * THE HOSTED ACCOUNT PAGE'S CHANGES (#844; ADR-017 Decision 8, ADR-020 §3).
 *
 * What the account page reads and changes for the person its browser session
 * belongs to, with the rules of the account API contract
 * (`@qauth-labs/shared-account-contract`) for each operation: its fresh
 * authentication, its refusals and its record. The page is the stand-in for
 * the design-system account console (#684–#688), which reaches the same
 * operations through the account API; until then the browser session is the
 * caller, and these functions hold the rules.
 *
 * - **Fresh authentication.** A change whose operation asks for it is made
 *   only while the session's sign-in is at most five minutes old and proved
 *   the account's strongest bound factor (`requiredFactorOf`: a passkey, else
 *   an authenticator app, else the password), or, where the operation lets
 *   it, used a recovery code in place of a lost one. A factor bound after a
 *   sign-in that proved only the password is no strongest factor while it is
 *   new (#1064; ADR-017 Decision 8, amended 2026-11-12), and the password
 *   alone, after a fresh sign-in, may remove it. A refusal is recorded as
 *   `request.account_operation_refused`, as the account API's guard records
 *   it, and the page sends the person through a fresh sign-in.
 * - **One lock per account.** A change to the account's credentials locks the
 *   user's row (`lockUser`), so a removal and its last-credential check never
 *   interleave with another change, and its event commits with it.
 * - **The last way in.** A removal that would leave no credential to sign in
 *   with (a marked credential, or the identity of a provider switched off,
 *   signs in with none: `signsInNow`) is refused with `last_credential`; one
 *   that would leave no second
 *   factor where the realm's policy requires one, with
 *   `second_factor_required`. An authenticator app is a second factor, never
 *   a way in on its own.
 *
 * Adding a passkey, setting up an authenticator app and linking an upstream
 * account are no changes here: each runs as an interaction of the sign-in
 * engine (`account-interaction.ts`), whose fresh sign-in comes first.
 */

/** A change of the account page, by the account API operation it stands for. */
export interface AccountPageChange {
  /** The operation's `operationId` in the account API contract. */
  readonly operationId: string;
  /** Its fresh-authentication rule, as the contract states it. */
  readonly freshAuthentication: 'none' | 'strongest-factor' | 'strongest-factor-or-recovery-code';
}

/** Every change the account page makes, with its contract operation. */
export const ACCOUNT_PAGE_CHANGES = {
  passwordChange: {
    operationId: 'account.password.change',
    freshAuthentication: 'strongest-factor',
  },
  passkeyRename: { operationId: 'account.passkeys.update', freshAuthentication: 'none' },
  passkeyRemove: {
    operationId: 'account.passkeys.delete',
    freshAuthentication: 'strongest-factor-or-recovery-code',
  },
  totpRemove: {
    operationId: 'account.totp.delete',
    freshAuthentication: 'strongest-factor-or-recovery-code',
  },
  recoveryCodesRegenerate: {
    operationId: 'account.recoveryCodes.regenerate',
    freshAuthentication: 'strongest-factor',
  },
  linkedAccountRemove: {
    operationId: 'account.linkedAccounts.delete',
    freshAuthentication: 'strongest-factor',
  },
  sessionEnd: { operationId: 'account.sessions.delete', freshAuthentication: 'none' },
  sessionsEndAll: { operationId: 'account.sessions.endAll', freshAuthentication: 'none' },
} as const satisfies Record<string, AccountPageChange>;

/** The credential a removal names: one passkey, or the account's authenticator app. */
export type CredentialTarget =
  | { readonly type: 'passkey'; readonly id: string }
  | { readonly type: 'totp' };

/** Whether `row` is the credential `target` names. */
function isTarget(
  row: { readonly id: string; readonly providerType: string },
  target: CredentialTarget
): boolean {
  return target.type === 'passkey'
    ? row.id === target.id && row.providerType === WEBAUTHN_PROVIDER_TYPE
    : row.providerType === TOTP_PROVIDER_TYPE;
}

/** Whether a session may make a change now, and why not. */
export type FreshAuthenticationVerdict =
  | { readonly kind: 'fresh' }
  | {
      readonly kind: 'refused';
      readonly reason: 'authentication_too_old' | 'strongest_factor_missing';
      readonly requiredFactor: AccountFactor;
    };

const REFUSED_EVENT = 'urn:qauth:event:request.account_operation_refused:v1-rc.0';

/**
 * Whether the browser session `session` may make `change` now: the account
 * API guard's rules (`checkAccountOperation`) on the session's own sign-in
 * instead of a token's claims. A refusal is recorded before it is answered.
 * A read that fails throws: a change is never made unchecked.
 *
 * A factor that is new (#1064; ADR-017 Decision 8, amended 2026-11-12) is no
 * strongest factor, and a sign-in that proved the strongest factor only
 * through a new one does not count. `removing` names the credential a
 * removal is for: while it is new, a fresh sign-in with the password alone
 * may remove it.
 */
export async function checkFreshAuthentication(
  fastify: FastifyInstance,
  request: FastifyRequest,
  session: BrowserSession,
  change: AccountPageChange,
  now: number = Date.now(),
  removing?: CredentialTarget
): Promise<FreshAuthenticationVerdict> {
  if (change.freshAuthentication === 'none') return { kind: 'fresh' };
  const credentials = (
    await fastify.repositories.userCredentials.findAllByUserId(session.userId)
  ).filter((row) => row.realmId === session.realmId);
  const requiredFactor = requiredFactorOf(credentials, session.realmId, now);
  const refuse = async (
    reason: 'authentication_too_old' | 'strongest_factor_missing'
  ): Promise<FreshAuthenticationVerdict> => {
    await emitUserEvent(
      request,
      REFUSED_EVENT,
      {
        operation: change.operationId,
        reason,
        ...(reason === 'strongest_factor_missing'
          ? { requiredFactor, maxAge: 0 }
          : { maxAge: FRESH_AUTHENTICATION_MAX_AGE_SECONDS }),
      },
      { realmId: session.realmId, userId: session.userId, clientId: null, actor: 'user' }
    );
    return { kind: 'refused', reason, requiredFactor };
  };
  if (!isFreshSignIn(session.authTime, now)) return refuse('authentication_too_old');
  // The password alone removes a credential while it is new (#1064).
  if (
    removing !== undefined &&
    session.amr.includes('pwd') &&
    credentials.some((row) => isTarget(row, removing) && isNewCredential(row, now))
  ) {
    return { kind: 'fresh' };
  }
  // The session's row, read once and only when a rule needs it: the cache
  // holds neither the recovery code nor the new credentials.
  let read: ReturnType<typeof fastify.repositories.sessions.findById> | undefined;
  const own = async () => {
    read ??= fastify.repositories.sessions.findById(session.realmId, session.sid);
    const row = await read;
    return row?.userId === session.userId ? row : undefined;
  };
  if (session.amr.includes(requiredFactor)) {
    if (!holdsNewFactor(requiredFactor, credentials, session.realmId, now)) {
      return { kind: 'fresh' };
    }
    const row = await own();
    if (
      row !== undefined &&
      !provedOnlyThroughNew(requiredFactor, row.newCredentialIds, credentials, session.realmId, now)
    ) {
      return { kind: 'fresh' };
    }
  }
  if (change.freshAuthentication === 'strongest-factor-or-recovery-code') {
    if ((await own())?.recoveryCodeUsed === true) return { kind: 'fresh' };
  }
  return refuse('strongest_factor_missing');
}

/** The account page's CSRF token of the session: read, or minted and kept with it. */
export async function accountCsrfToken(
  fastify: FastifyInstance,
  session: BrowserSession
): Promise<string> {
  const { accountCsrfToken: held } = await readSessionSideRecord(fastify, session);
  if (held !== undefined && held.length > 0) return held;
  const token = generateCsrfToken();
  // The side record expires with the session, never extending it.
  await writeSessionSideRecord(fastify, session, { accountCsrfToken: token });
  return token;
}

/**
 * Whether a form post carries the session's account CSRF token. A post
 * without it, or with another, is recorded as `request.csrf_rejected`.
 */
export async function accountCsrfAccepted(
  fastify: FastifyInstance,
  request: FastifyRequest,
  session: BrowserSession,
  provided: string | undefined
): Promise<boolean> {
  const { accountCsrfToken: held } = await readSessionSideRecord(fastify, session);
  if (held !== undefined && held.length > 0 && csrfTokensEqual(provided, held)) return true;
  await emitUserEvent(
    request,
    'urn:qauth:event:request.csrf_rejected:v1-rc.0',
    { form: 'account' },
    { realmId: session.realmId, userId: session.userId, clientId: null, actor: 'user' }
  );
  return false;
}

/** A credential row, as far as these rules read it. */
interface CredentialRow {
  readonly id: string;
  readonly providerType: string;
  readonly realmId: string;
  /** The failure ladder's mark, or a rebind's (#655). */
  readonly disabledAt?: number | null;
}

/**
 * Whether a credential still signs in: one the failure ladder or a rebind
 * marked does not, until a reset or a new set-up, so it is no way in that a
 * removal may leave the account with.
 */
function isLive(credential: CredentialRow): boolean {
  return credential.disabledAt === null || credential.disabledAt === undefined;
}

/** Whether a credential is a second factor: a passkey or an authenticator app. */
function isSecondFactor(credential: CredentialRow): boolean {
  return (
    credential.providerType === WEBAUTHN_PROVIDER_TYPE ||
    credential.providerType === TOTP_PROVIDER_TYPE
  );
}

/**
 * Whether the realm's MFA policy requires a second factor of the account,
 * as the engine reads it (`secondFactorRequired`): `required`, or
 * `required_for_admins` for an account holding an admin grant.
 */
async function secondFactorRequired(
  fastify: FastifyInstance,
  realmId: string,
  userId: string
): Promise<boolean> {
  // As the engines read it: the test support's reader, or none required.
  const policy = await (fastify.signInMfaPolicy ?? NO_SECOND_FACTOR_POLICY).read({
    realmId,
    clientId: ACCOUNT_PAGES_ENGINE_CLIENT_ID,
  });
  const modes = [policy.realm, policy.client];
  if (modes.includes('required')) return true;
  if (!modes.includes('required_for_admins')) return false;
  return (await fastify.repositories.adminGrants.listLive(realmId, userId)).length > 0;
}

// ── The overview ─────────────────────────────────────────────────────────────

/** One passkey of the account, as the page shows it. */
export interface AccountPasskey {
  readonly id: string;
  readonly nickname: string | null;
  readonly createdAt: number;
  readonly lastUsedAt: number | null;
  readonly backedUp: boolean;
  /** The failure ladder's mark, or a rebind's: it signs in no more. */
  readonly disabled: boolean;
  /**
   * When it stops being new (#1064), while it is: it was bound after a
   * sign-in that proved only the password, and the password alone may
   * remove it until then.
   */
  readonly newUntil?: number;
}

/**
 * A factor bound after a sign-in that proved only the password, still new
 * (#1064; ADR-017 Decision 8, amended 2026-11-12), that the session the page
 * is shown in did not bind or prove: the page tells of it, with "not you?
 * remove it".
 */
export interface AccountNewBinding {
  readonly type: 'passkey' | 'totp';
  /** The credential's id: the passkey's in its removal path. */
  readonly id: string;
  readonly addedAt: number;
  readonly newUntil: number;
}

/** One live session of the account, as the page shows it. */
export interface AccountSession {
  readonly sid: string;
  readonly current: boolean;
  readonly createdAt: number;
  readonly lastSeenAt: number;
  readonly userAgent: string | null;
  readonly ipAddress: string | null;
  readonly clients: readonly string[];
}

/** Everything the overview shows. */
export interface AccountOverview {
  readonly password: { readonly set: boolean; readonly address?: string };
  readonly passkeys: readonly AccountPasskey[];
  readonly totp: { readonly set: boolean; readonly newUntil?: number };
  /** The new factors this session did not bind or prove, oldest first (#1064). */
  readonly newBindings: readonly AccountNewBinding[];
  readonly recoveryCodes: { readonly issued: boolean; readonly unused: number };
  readonly linkedAccounts: readonly LinkedAccount[];
  /** The realm's providers the account holds no identity of: what it may link. */
  readonly linkable: readonly { readonly provider: string; readonly name: string }[];
  readonly sessions: readonly AccountSession[];
  readonly requiredFactor: AccountFactor;
}

/** The most sessions the page lists; the rest are ended by "sign out everywhere". */
export const ACCOUNT_PAGE_SESSION_LIMIT = 50;

/** The account's sign-in methods and live sessions, for the overview. */
export async function readAccountOverview(
  fastify: FastifyInstance,
  engines: InteractionEngines,
  session: BrowserSession,
  now: number = Date.now()
): Promise<AccountOverview> {
  const { realmId, userId } = session;
  const credentials = (await fastify.repositories.userCredentials.findAllByUserId(userId)).filter(
    (credential) => credential.realmId === realmId
  );
  const password = credentials.find((row) => row.providerType === PASSWORD_PROVIDER_TYPE);
  const passkeys = credentials
    .filter((row) => row.providerType === WEBAUTHN_PROVIDER_TYPE)
    .flatMap((row): AccountPasskey[] => {
      const data = webauthnCredentialDataSchema.safeParse(row.credentialData);
      if (!data.success) return [];
      return [
        {
          id: row.id,
          nickname: data.data.nickname,
          createdAt: data.data.created_at,
          lastUsedAt: data.data.last_used_at,
          backedUp: data.data.backed_up,
          disabled: row.disabledAt !== null && row.disabledAt !== undefined,
          ...(isNewCredential(row, now) ? { newUntil: row.newUntil as number } : {}),
        },
      ];
    })
    .sort((a, b) => b.createdAt - a.createdAt);
  const totp = credentials.find((row) => row.providerType === TOTP_PROVIDER_TYPE);
  // The new factors (#1064), but those this session bound or proved: its
  // row names them, which the cache does not hold.
  const fresh = credentials.filter(
    (row) =>
      (row.providerType === WEBAUTHN_PROVIDER_TYPE || row.providerType === TOTP_PROVIDER_TYPE) &&
      isNewCredential(row, now)
  );
  const named =
    fresh.length === 0
      ? []
      : ((await fastify.repositories.sessions.findById(realmId, session.sid))?.newCredentialIds ??
        []);
  const newBindings = fresh
    .filter((row) => !named.includes(row.id))
    .map((row): AccountNewBinding => ({
      type: row.providerType === TOTP_PROVIDER_TYPE ? 'totp' : 'passkey',
      id: row.id,
      addedAt: row.createdAt,
      newUntil: row.newUntil as number,
    }))
    .sort((a, b) => a.addedAt - b.addedAt);
  const recovery = await engines.recoveryCodes.status({ realmId, userId });
  const linked = await pageLinkedAccounts(fastify, realmId, userId, {
    list: 'ui.account.linkedAccounts',
    limit: 100,
    cursor: undefined,
  });
  const holds = new Set(linked.items.map((item) => item.provider));
  const linkable = (await upstreamProviderCatalog(fastify).offered(realmId))
    .filter((entry) => !holds.has(entry.provider))
    .map((entry) => ({ provider: entry.provider, name: entry.name }));
  const page = await fastify.sessionService.listForUser({
    realmId,
    userId,
    page: { limit: ACCOUNT_PAGE_SESSION_LIMIT },
  });
  return {
    password: {
      set: password !== undefined,
      ...(password === undefined ? {} : { address: password.externalSub }),
    },
    passkeys,
    totp: {
      set: totp !== undefined,
      ...(totp !== undefined && isNewCredential(totp, now)
        ? { newUntil: totp.newUntil as number }
        : {}),
    },
    newBindings,
    recoveryCodes: { issued: recovery.issued, unused: recovery.unused },
    linkedAccounts: linked.items,
    linkable,
    sessions: page.items
      .filter((item: ListedSession) => item.state === 'live')
      .map((item) => ({
        sid: item.sid,
        current: item.sid === session.sid,
        createdAt: item.createdAt,
        lastSeenAt: item.lastSeenAt,
        userAgent: item.userAgent,
        ipAddress: item.ipAddress,
        clients: item.clients.map((client) => client.name),
      })),
    requiredFactor: requiredFactorOf(credentials, realmId, now),
  };
}

// ── The password ─────────────────────────────────────────────────────────────

/** What a password change did. */
export type PasswordChangeResult =
  | { readonly kind: 'changed' }
  /** The account has no password: setting a first one is no change here. */
  | { readonly kind: 'no_password' }
  /**
   * The current password was wrong, and it counted on the failure ladder; or
   * a reset replaced it while the change was made, and nothing was written.
   */
  | { readonly kind: 'wrong_password' }
  /** The ladder holds the account's password attempts back. */
  | { readonly kind: 'wait'; readonly retryAfterSeconds: number }
  /** The new password breaks the realm's policy or is on its breach list: the messages say why. */
  | { readonly kind: 'rejected'; readonly messages: readonly string[] }
  /** The ladder's store could not be reached: nothing was checked. */
  | { readonly kind: 'unavailable' };

/** The breach list's message, as registration gives it. */
export const BREACHED_PASSWORD_MESSAGE =
  'This password appears in a list of passwords exposed in data breaches';

/**
 * Replace the account's password, with the current one (`account.password.change`).
 * The caller has checked a fresh sign-in with the strongest factor and the
 * form's CSRF token.
 *
 * The current password is checked as a sign-in checks it, reserved on the
 * account's failure ladder first, so a wrong one counts. The new one meets
 * the realm's one password policy (#634) and its breach list. In one
 * transaction the new hash is written, over the hash just checked only (a
 * reset that committed meanwhile replaced it, and the change writes
 * nothing), the account's `update_password` action cleared, its unredeemed
 * codes and refresh tokens ended (a refresh family names no session, so none
 * of them is this session's to keep) and `user.password_changed` recorded.
 * Then every sign-in in progress that began before ends at its next round
 * (`recordPasswordChange`), every other browser session ends, this one
 * stays, and the "password changed" notice goes out.
 */
export async function changePassword(
  fastify: FastifyInstance,
  request: FastifyRequest,
  session: BrowserSession,
  input: { readonly current: string; readonly next: string; readonly mailer: EngineMailer }
): Promise<PasswordChangeResult> {
  const realm = requestRealm(request);
  const { userId } = session;
  const credential = await fastify.repositories.userCredentials.findByUserIdAndType(
    userId,
    PASSWORD_PROVIDER_TYPE
  );
  if (credential === undefined || credential.realmId !== realm.id) return { kind: 'no_password' };
  const stored = passwordCredentialDataSchema.safeParse(credential.credentialData);
  // Never the data itself: it holds the hash.
  if (!stored.success) throw new Error('malformed credential_data on a password credential');

  let attempt: PasswordAttempt;
  try {
    attempt = await fastify.passwordAttempts.reserve({
      realmId: realm.id,
      identifier: credential.externalSub,
      ...ladderEndUserIp(request),
    });
  } catch (error) {
    if (!(error instanceof SignInStoreUnavailableError)) throw error;
    fastify.log.error({ err: error, port: error.port }, 'sign-in failure ladder unavailable');
    return { kind: 'unavailable' };
  }
  if (attempt.kind === 'wait')
    return { kind: 'wait', retryAfterSeconds: attempt.retryAfterSeconds };
  const marked = credential.disabledAt !== null && credential.disabledAt !== undefined;
  if (marked && (await fastify.passwordAttempts.hardActionArmed(realm.id))) {
    await attempt.failed(async () => null);
    return { kind: 'wrong_password' };
  }
  const valid = await fastify.passwordHasher.verifyPassword(
    stored.data.password_hash,
    presentedPasswordFor(stored.data, input.current)
  );
  if (!valid) {
    await attempt.failed(async () => ({ userId }));
    return { kind: 'wrong_password' };
  }
  await attempt.succeeded({ userId, ignoredMark: marked });

  const policies = accountPoliciesOf(fastify, realm);
  const checked = fastify.passwordValidators
    .forPolicy({ minLength: policies.passwordMinLength, minScore: policies.passwordMinScore })
    .check(input.next, {
      email: credential.externalSub,
      serviceName: policies.serviceName,
      realmName: realm.name,
    });
  if (!checked.valid) return { kind: 'rejected', messages: [...checked.feedback] };
  const breach = await fastify.breachedPasswords.check(realm, checked.password);
  if (breach.kind === 'listed') return { kind: 'rejected', messages: [BREACHED_PASSWORD_MESSAGE] };
  if (breach.kind === 'failed') {
    await emitUserEvent(
      request,
      'urn:qauth:event:user.password_breach_check_failed:v1-rc.0',
      { reason: breach.reason },
      { realmId: realm.id, userId, clientId: null, actor: 'user' }
    );
  }

  const passwordHash = await fastify.passwordHasher.hashPassword(checked.password);
  const written = await fastify.db.transaction(async (tx): Promise<boolean> => {
    // Over the hash the current password was checked against only: a reset
    // that committed since replaced it, and its password stays.
    const updated = await fastify.repositories.userCredentials.updatePassword(
      realm.id,
      credential.id,
      buildPasswordCredentialData(passwordHash, stored.data.email_verified, checked.normalization),
      tx,
      { expectedPasswordHash: stored.data.password_hash }
    );
    if (updated === undefined) return false;
    if (updated.userId !== userId) throw new Error('the password credential changed hands');
    await fastify.repositories.userRequiredActions.remove(realm.id, userId, 'update_password', tx);
    await fastify.repositories.authorizationCodes.invalidateForUser(userId, tx);
    await fastify.repositories.refreshTokens.revokeAllForUser(userId, 'password_changed', tx);
    await emitUserEvent(
      request,
      'urn:qauth:event:user.password_changed:v1-rc.0',
      {},
      { tx, realmId: realm.id, userId, clientId: null, actor: 'user' }
    );
    return true;
  });
  if (!written) return { kind: 'wrong_password' };

  // None of these can undo the change, and none may fail it: each is logged.
  // The cutoff first: a sign-in that proved the old password and finishes
  // after it gets no session, and one that finished before is ended below.
  try {
    await recordPasswordChange(fastify, realm.id, userId, Date.now());
  } catch (error) {
    fastify.log.error(
      { err: error, realmId: realm.id },
      'a password changed, but the sign-ins in progress could not be ended'
    );
  }
  try {
    await endBrowserSessions(fastify, realm.id, userId, {
      reason: 'reset',
      exceptSid: session.sid,
    });
  } catch (error) {
    fastify.log.error(
      { err: error, realmId: realm.id },
      'a password changed, but the other sessions could not be ended'
    );
  }
  input.mailer.sendUncounted(realm, credential.externalSub, { template: 'password_changed' });
  return { kind: 'changed' };
}

// ── Passkeys and the authenticator app ───────────────────────────────────────

/** What a removal did. */
export type CredentialRemovalResult =
  | { readonly kind: 'removed' }
  /** No such credential of the account: another account's reads the same. */
  | { readonly kind: 'not_found' }
  /** It is the account's last way to sign in. */
  | { readonly kind: 'last_credential' }
  /** It is the last second factor the realm's policy requires of the account. */
  | { readonly kind: 'second_factor_required' };

/**
 * Remove one of the account's passkeys (`account.passkeys.delete`) or its
 * authenticator app (`account.totp.delete`), under the user's row lock. The
 * caller has checked a fresh sign-in and the CSRF token. The delete and its
 * `user.credential_removed` event commit together; then the owner is told at
 * the address of the account's password (ADR-020 §3 "Emails": a notice no
 * realm switches off). An account with no password has no address to tell.
 *
 * A credential removed while it is new (#1064; ADR-017 Decision 8, amended
 * 2026-11-12) takes with it what it opened: in the removal's transaction,
 * the unredeemed codes of every session whose sign-in bound or proved it,
 * live or ended (a family outlives its browser session), the refresh
 * families those sign-ins opened (a family carries its session's
 * `auth_time`, #662), and the account's recovery codes, which may have been
 * shown with it. Then every sign-in in progress of the account ends at its
 * next round (the password change's cutoff, `recordPasswordChange`), so none
 * that proved the credential or took one of those codes binds a factor
 * after it; the live sessions end; and the codes and families are swept once
 * more, for one a session minted meanwhile. The event says so (`whileNew`).
 */
export async function removeCredential(
  fastify: FastifyInstance,
  request: FastifyRequest,
  session: BrowserSession,
  target: CredentialTarget,
  mailer: EngineMailer,
  now: number = Date.now()
): Promise<CredentialRemovalResult> {
  const { realmId, userId } = session;
  const mfaRequired = await secondFactorRequired(fastify, realmId, userId);
  let address: string | undefined;
  /** Whether the removed credential was new: what it opened is ended after the commit too. */
  let removedWhileNew = false;
  /** The sessions, live or ended, whose sign-in bound or proved the removed new credential. */
  let opened: readonly {
    readonly id: string;
    readonly authTime: number;
    readonly live: boolean;
  }[] = [];
  const result = await fastify.db.transaction(async (tx): Promise<CredentialRemovalResult> => {
    if (!(await fastify.repositories.userCredentials.lockUser(realmId, userId, tx))) {
      return { kind: 'not_found' };
    }
    const held = (await fastify.repositories.userCredentials.findAllByUserId(userId, tx)).filter(
      (row) => row.realmId === realmId
    );
    const row = held.find((candidate) => isTarget(candidate, target));
    if (row === undefined) return { kind: 'not_found' };
    // What the account keeps that still signs in: a marked credential is
    // none, nor the identity of a provider switched off.
    const others = held.filter((candidate) => candidate.id !== row.id && isLive(candidate));
    if (!(await signsInNow(fastify, realmId, others))) return { kind: 'last_credential' };
    if (mfaRequired && !others.some(isSecondFactor)) return { kind: 'second_factor_required' };
    const whileNew = isNewCredential(row, now);
    const deleted = await fastify.repositories.userCredentials.deleteById(realmId, row.id, tx);
    if (deleted === undefined || deleted.userId !== userId) {
      throw new Error('a locked credential could not be deleted');
    }
    if (whileNew) {
      removedWhileNew = true;
      opened = (
        await fastify.repositories.sessions.listNamingCredential(realmId, userId, row.id, tx)
      ).map((candidate) => ({
        id: candidate.id,
        authTime: candidate.authTime,
        live: candidate.revokedAt === null && candidate.expiresAt > now,
      }));
      await revokeWhatOpened(fastify, userId, opened, tx);
      await fastify.repositories.userRecoveryCodes.deleteSet(realmId, userId, tx);
    }
    const data = webauthnCredentialDataSchema.safeParse(row.credentialData);
    await emitUserEvent(
      request,
      'urn:qauth:event:user.credential_removed:v1-rc.0',
      {
        type: target.type,
        credentialId: row.id,
        ...(target.type === 'totp'
          ? { authenticator: 'app' as const }
          : data.success
            ? { authenticator: passkeyAuthenticatorOf(data.data) }
            : {}),
        ...(whileNew ? { whileNew: true as const } : {}),
      },
      { tx, realmId, userId, clientId: null, actor: 'user' }
    );
    address = held.find(
      (candidate) => candidate.providerType === PASSWORD_PROVIDER_TYPE
    )?.externalSub;
    return { kind: 'removed' };
  });
  if (result.kind === 'removed' && removedWhileNew) {
    // None of these can undo the removal, whose transaction already revoked
    // the sessions' codes and families and deleted the recovery codes, and
    // none may fail it: each is logged. The cutoff first: a sign-in in
    // progress that proved the credential, or took a code of the deleted
    // set, binds nothing after it. Each live session's clients are queued a
    // back-channel logout by its revocation (#624). A `reset`: a
    // credential's removal ended it.
    try {
      await recordPasswordChange(fastify, realmId, userId, Date.now());
    } catch (error) {
      fastify.log.error(
        { err: error, realmId },
        'a new credential was removed, but the sign-ins in progress could not be ended'
      );
    }
    for (const { id } of opened.filter((candidate) => candidate.live)) {
      try {
        await endBrowserSession(
          fastify,
          realmId,
          id,
          'reset',
          { type: 'user', id: userId },
          userId
        );
      } catch (error) {
        fastify.log.error(
          { err: error, realmId },
          'a new credential was removed, but a session it opened could not be ended'
        );
      }
    }
    try {
      await revokeWhatOpened(fastify, userId, opened);
    } catch (error) {
      fastify.log.error(
        { err: error, realmId },
        'a new credential was removed, but the second sweep of what it opened failed'
      );
    }
  }
  if (result.kind === 'removed' && address !== undefined) {
    // Queued, never awaited: a notice that cannot go out is logged by the mailer.
    mailer.sendUncounted(requestRealm(request), address, {
      template: target.type === 'passkey' ? 'passkey_removed' : 'totp_removed',
    });
  }
  return result;
}

/**
 * End the unredeemed codes the `sessions` minted and the refresh families
 * their sign-ins opened (#1064): codes first, so one redeemed meanwhile
 * opens no family after the sweep.
 */
async function revokeWhatOpened(
  fastify: FastifyInstance,
  userId: string,
  sessions: readonly { readonly id: string; readonly authTime: number }[],
  tx?: Parameters<Parameters<FastifyInstance['db']['transaction']>[0]>[0]
): Promise<void> {
  if (sessions.length === 0) return;
  await fastify.repositories.authorizationCodes.invalidateForSessions(
    userId,
    sessions.map(({ id }) => id),
    tx
  );
  await fastify.repositories.refreshTokens.revokeFamiliesOfSignIns(
    userId,
    sessions.map(({ authTime }) => authTime),
    'new_credential_removed',
    tx
  );
}

/**
 * Rename one of the account's passkeys (`account.passkeys.update`): a name is
 * no credential, so it needs no fresh sign-in (ADR-020 §3). The name is tidied
 * as an enrolment tidies it; an empty one removes it. The write and its
 * `user.passkey_renamed` event commit together.
 */
export async function renamePasskey(
  fastify: FastifyInstance,
  request: FastifyRequest,
  session: BrowserSession,
  input: { readonly id: string; readonly nickname: string }
): Promise<{ readonly kind: 'renamed' | 'not_found' }> {
  const { realmId, userId } = session;
  return fastify.db.transaction(async (tx) => {
    if (!(await fastify.repositories.userCredentials.lockUser(realmId, userId, tx))) {
      return { kind: 'not_found' as const };
    }
    const row = (await fastify.repositories.userCredentials.findAllByUserId(userId, tx)).find(
      (candidate) =>
        candidate.id === input.id &&
        candidate.realmId === realmId &&
        candidate.providerType === WEBAUTHN_PROVIDER_TYPE
    );
    if (row === undefined) return { kind: 'not_found' as const };
    const data = webauthnCredentialDataSchema.safeParse(row.credentialData);
    if (!data.success) throw new Error('a passkey whose credential_data is not one');
    await fastify.repositories.userCredentials.updateCredentialData(
      row.id,
      { ...row.credentialData, nickname: normalisePasskeyNickname(input.nickname) },
      tx
    );
    await emitUserEvent(
      request,
      'urn:qauth:event:user.passkey_renamed:v1-rc.0',
      { credentialId: row.id },
      { tx, realmId, userId, clientId: null, actor: 'user' }
    );
    return { kind: 'renamed' as const };
  });
}

// ── Recovery codes ───────────────────────────────────────────────────────────

/** What a regeneration did. */
export type RecoveryCodesResult =
  | { readonly kind: 'issued'; readonly codes: readonly string[]; readonly setId: string }
  /** The account holds no second factor and no passkey: a set would stand in for nothing. */
  | { readonly kind: 'conflict' };

/**
 * Issue a new set of recovery codes (`account.recoveryCodes.regenerate`),
 * returned once: every code of the old set stops working, and the notice
 * goes out. The caller has checked a fresh sign-in with the strongest factor
 * and the CSRF token, and shows the codes with `Cache-Control: no-store`.
 * The store writes the set itself, so `user.recovery_codes_regenerated` is
 * recorded right after it; a record that fails is logged, and the codes are
 * still shown: the old set is gone either way.
 */
export async function regenerateRecoveryCodes(
  fastify: FastifyInstance,
  request: FastifyRequest,
  engines: InteractionEngines,
  session: BrowserSession
): Promise<RecoveryCodesResult> {
  const { realmId, userId } = session;
  const held = (await fastify.repositories.userCredentials.findAllByUserId(userId)).filter(
    (row) => row.realmId === realmId
  );
  if (!held.some(isSecondFactor)) return { kind: 'conflict' };
  const set = await engines.forRequest(request, () =>
    engines.recoveryCodes.regenerate({ realmId, userId })
  );
  try {
    await emitUserEvent(
      request,
      'urn:qauth:event:user.recovery_codes_regenerated:v1-rc.0',
      {},
      { realmId, userId, clientId: null, actor: 'user' }
    );
  } catch (error) {
    fastify.log.error({ err: error, realmId }, 'recovery codes were regenerated, but not recorded');
  }
  return { kind: 'issued', codes: set.codes, setId: set.setId };
}

// ── Sessions ─────────────────────────────────────────────────────────────────

/**
 * End one of the account's sessions (`account.sessions.delete`): its cookie
 * stops working, and every client it signed in to is queued a back-channel
 * logout by the revocation itself (#624). Recorded as `user.signed_out` with
 * its `sid`. A session of another account is `not_found`, untouched.
 */
export async function endAccountSession(
  fastify: FastifyInstance,
  request: FastifyRequest,
  session: BrowserSession,
  sid: string
): Promise<{ readonly kind: 'ended' | 'not_found' }> {
  const { realmId, userId } = session;
  const outcome = await endBrowserSession(
    fastify,
    realmId,
    sid,
    'sign_out',
    { type: 'user', id: userId },
    userId
  );
  if (outcome !== 'ended') return { kind: 'not_found' };
  await emitUserEvent(
    request,
    'urn:qauth:event:user.signed_out:v1-rc.0',
    { sid },
    { realmId, userId, clientId: null, actor: 'user' }
  );
  return { kind: 'ended' };
}

/**
 * Sign out everywhere (`account.sessions.endAll`): every session of the
 * account ends, this one too, each client it signed in to is queued a
 * back-channel logout, and every unredeemed code and refresh token of the
 * account ends, as `POST /auth/logout` ends them. Recorded as
 * `user.signed_out` without a `sid`.
 */
export async function endAllAccountSessions(
  fastify: FastifyInstance,
  request: FastifyRequest,
  session: BrowserSession
): Promise<void> {
  const { realmId, userId } = session;
  await endBrowserSessions(fastify, realmId, userId);
  // Codes first: one redeemed after the sweep below would mint a refresh
  // token that survives it.
  await fastify.repositories.authorizationCodes.invalidateForUser(userId);
  await fastify.repositories.refreshTokens.revokeAllForUser(userId, 'logout');
  await emitUserEvent(
    request,
    'urn:qauth:event:user.signed_out:v1-rc.0',
    {},
    { realmId, userId, clientId: null, actor: 'user' }
  );
}
