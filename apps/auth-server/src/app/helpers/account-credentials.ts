import {
  normalisePasskeyNickname,
  PASSWORD_PROVIDER_TYPE,
  WEBAUTHN_PROVIDER_TYPE,
  webauthnCredentialDataSchema,
} from '@qauth-labs/fastify-plugin-federation';
import {
  NO_SECOND_FACTOR_POLICY,
  TOTP_PROVIDER_TYPE,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { type CredentialTarget, isTargetCredential } from './account-operation-guard';
import { type AccountPasskey, passkeyOf } from './account-sign-in-methods';
import { endBrowserSession } from './browser-session';
import type { EngineMailer } from './engine-mail';
import { ACCOUNT_PAGES_ENGINE_CLIENT_ID } from './interaction-record';
import { isNewCredential, passkeyAuthenticatorOf } from './new-factors';
import { recordPasswordChange } from './password-reset';
import { requestRealm } from './request-realm';
import { signsInNow } from './upstream-links';
import { emitUserEvent } from './user-events';

export type { CredentialTarget } from './account-operation-guard';

/**
 * THE PASSKEY AND AUTHENTICATOR APP CHANGES (#844, #1108; ADR-017 Decision 8,
 * ADR-020 §3): renaming a passkey (`account.passkeys.update`) and removing a
 * passkey (`account.passkeys.delete`) or the authenticator app
 * (`account.totp.delete`), which the hosted account page makes behind its
 * browser session and the account API behind an account-audience token. Each
 * caller checks its own admission first (the page its CSRF value, both the
 * fresh sign-in each operation asks for); what the change does is here alone.
 *
 * - **One lock per account.** A change to the account's credentials locks the
 *   user's row (`lockUser`), so a removal and its last-credential check never
 *   interleave with another change, and its event commits with it.
 * - **The last way in.** A removal that would leave no credential to sign in
 *   with (a marked credential, or the identity of a provider switched off,
 *   signs in with none: `signsInNow`) is refused with `last_credential`; one
 *   that would leave no second factor where the realm's policy requires one,
 *   with `second_factor_required`. An authenticator app is a second factor,
 *   never a way in on its own.
 */

/** The account a change is made to, and the client it came through. */
export interface AccountOwner {
  readonly realmId: string;
  readonly userId: string;
  /**
   * The OAuth client the change came through: the account API's caller. The
   * hosted page is no client, so its events name none.
   */
  readonly clientId?: string | null;
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
export function isSecondFactor(credential: { readonly providerType: string }): boolean {
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

// ── Removal ──────────────────────────────────────────────────────────────────

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
 * caller has checked a fresh sign-in (and, on the page, the CSRF token). The
 * delete and its `user.credential_removed` event commit together; then the
 * owner is told at the address of the account's password (ADR-020 §3
 * "Emails": a notice no realm switches off). An account with no password has
 * no address to tell.
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
  owner: AccountOwner,
  target: CredentialTarget,
  mailer: EngineMailer,
  now: number = Date.now()
): Promise<CredentialRemovalResult> {
  const { realmId, userId } = owner;
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
    const row = held.find((candidate) => isTargetCredential(candidate, target));
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
      { tx, realmId, userId, clientId: owner.clientId ?? null, actor: 'user' }
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

// ── Rename ───────────────────────────────────────────────────────────────────

/** What a rename did. */
export type PasskeyRenameResult =
  /** The passkey as it is now, renamed. */
  | { readonly kind: 'renamed'; readonly passkey: AccountPasskey }
  /** No such passkey of the account: another account's reads the same. */
  | { readonly kind: 'not_found' }
  /** The caller's precondition refused the passkey as it was: nothing was written. */
  | { readonly kind: 'precondition_failed' };

/**
 * Rename one of the account's passkeys (`account.passkeys.update`): a name is
 * no credential, so it needs no fresh sign-in (ADR-020 §3). The name is tidied
 * as an enrolment tidies it; an empty one removes it. Under the user's row
 * lock, `precondition` reads the passkey as it is before the write (the
 * account API's `If-Match`); the write and its `user.passkey_renamed` event
 * commit together.
 */
export async function renamePasskey(
  fastify: FastifyInstance,
  request: FastifyRequest,
  owner: AccountOwner,
  input: {
    readonly id: string;
    readonly nickname: string;
    readonly precondition?: (current: AccountPasskey) => boolean;
  },
  now: number = Date.now()
): Promise<PasskeyRenameResult> {
  const { realmId, userId } = owner;
  return fastify.db.transaction(async (tx): Promise<PasskeyRenameResult> => {
    if (!(await fastify.repositories.userCredentials.lockUser(realmId, userId, tx))) {
      return { kind: 'not_found' };
    }
    const row = (await fastify.repositories.userCredentials.findAllByUserId(userId, tx)).find(
      (candidate) =>
        candidate.id === input.id &&
        candidate.realmId === realmId &&
        candidate.providerType === WEBAUTHN_PROVIDER_TYPE
    );
    if (row === undefined) return { kind: 'not_found' };
    const current = passkeyOf(row, now);
    if (current === undefined) throw new Error('a passkey whose credential_data is not one');
    if (input.precondition !== undefined && !input.precondition(current)) {
      return { kind: 'precondition_failed' };
    }
    const credentialData = {
      ...row.credentialData,
      nickname: normalisePasskeyNickname(input.nickname),
    };
    await fastify.repositories.userCredentials.updateCredentialData(row.id, credentialData, tx);
    await emitUserEvent(
      request,
      'urn:qauth:event:user.passkey_renamed:v1-rc.0',
      { credentialId: row.id },
      { tx, realmId, userId, clientId: owner.clientId ?? null, actor: 'user' }
    );
    const renamed = passkeyOf({ ...row, credentialData }, now);
    if (renamed === undefined) throw new Error('a renamed passkey is no passkey');
    return { kind: 'renamed', passkey: renamed };
  });
}
