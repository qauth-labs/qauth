import { WEBAUTHN_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-federation';
import type { BrowserSession, ListedSession } from '@qauth-labs/fastify-plugin-sessions';
import { TOTP_PROVIDER_TYPE } from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { isSecondFactor } from './account-credentials';
import {
  type AccountFactor,
  type CredentialTarget,
  FRESH_AUTHENTICATION_MAX_AGE_SECONDS,
  holdsNewFactor,
  isFreshSignIn,
  isTargetCredential,
  provedOnlyThroughNew,
  requiredFactorOf,
} from './account-operation-guard';
import {
  accountCredentials,
  type AccountPasskey,
  signInMethodsOf,
} from './account-sign-in-methods';
import { endBrowserSession, endBrowserSessions } from './browser-session';
import type { InteractionEngines } from './interaction-engines';
import { isNewCredential } from './new-factors';
import { csrfTokensEqual, generateCsrfToken } from './session-cookie';
import { readSessionSideRecord, writeSessionSideRecord } from './session-side-record';
import { type LinkedAccount, pageLinkedAccounts } from './upstream-links';
import { upstreamProviderCatalog } from './upstream-providers';
import { emitUserEvent } from './user-events';

export {
  type CredentialRemovalResult,
  type CredentialTarget,
  type PasskeyRenameResult,
  removeCredential,
  renamePasskey,
} from './account-credentials';
export type { AccountPasskey } from './account-sign-in-methods';

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
 * engine (`account-interaction.ts`), whose fresh sign-in comes first. The
 * password change, the sign-in methods' read and the passkey and
 * authenticator app changes are the account API's too, so they live apart
 * (`account-password-change.ts`, `account-sign-in-methods.ts`,
 * `account-credentials.ts`), where its routes reach them without the rest of
 * the page (#1107, #1108).
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
    credentials.some((row) => isTargetCredential(row, removing) && isNewCredential(row, now))
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

// ── The overview ─────────────────────────────────────────────────────────────

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

/**
 * The account's sign-in methods and live sessions, for the overview: the
 * methods as the account API reads them too (`signInMethodsOf`), with what
 * only the page shows beside them.
 */
export async function readAccountOverview(
  fastify: FastifyInstance,
  session: BrowserSession,
  now: number = Date.now()
): Promise<AccountOverview> {
  const { realmId, userId } = session;
  const credentials = await accountCredentials(fastify, realmId, userId);
  const methods = await signInMethodsOf(fastify, realmId, userId, credentials, now);
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
      set: methods.password.set,
      ...(methods.password.address === undefined ? {} : { address: methods.password.address }),
    },
    passkeys: methods.passkeys,
    totp: methods.totp,
    newBindings,
    recoveryCodes: methods.recoveryCodes,
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
    requiredFactor: methods.requiredFactor,
  };
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
