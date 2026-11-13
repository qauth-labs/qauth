import {
  buildPasswordCredentialData,
  PASSWORD_PROVIDER_TYPE,
  passwordCredentialDataSchema,
  presentedPasswordFor,
} from '@qauth-labs/fastify-plugin-federation';
import {
  type PasswordAttempt,
  SignInStoreUnavailableError,
} from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { PasswordRejectionReason } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyRequest } from 'fastify';

import { accountPoliciesOf } from './account-policies';
import { endBrowserSessions } from './browser-session';
import type { EngineMailer } from './engine-mail';
import { ladderEndUserIp } from './password-attempts';
import { recordPasswordChange } from './password-reset';
import { requestRealm } from './request-realm';
import { emitUserEvent } from './user-events';

/**
 * THE PASSWORD CHANGE (`account.password.change`; #844, #1107; ADR-017
 * Decision 8, ADR-020 §3): the one change of a password with the current
 * one, which the hosted account page makes behind its browser session and
 * the account API behind an account-audience token. Each caller checks its
 * own admission first (the page its CSRF value, both the fresh sign-in with
 * the account's strongest factor); what the change does is here alone.
 */

/** Why a new password was refused: the password policy's reasons, or the breach list's. */
export type PasswordChangeRejection = PasswordRejectionReason | 'breached';

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
  /**
   * The new password breaks the realm's policy or is on its breach list: the
   * messages say why to a person, the reasons to a program.
   */
  | {
      readonly kind: 'rejected';
      readonly messages: readonly string[];
      readonly reasons: readonly PasswordChangeRejection[];
    }
  /** The ladder's store could not be reached: nothing was checked. */
  | { readonly kind: 'unavailable' };

/** The breach list's message, as registration gives it. */
export const BREACHED_PASSWORD_MESSAGE =
  'This password appears in a list of passwords exposed in data breaches';

/** Whose password changes, and where the change was made. */
export interface PasswordChanger {
  /** The account whose password changes. */
  readonly userId: string;
  /**
   * The browser session the change was made in: the hosted page's own, or
   * the one an account API token names in `sid`. It stays signed in, and
   * every other session of the account ends. Without one, every one ends.
   */
  readonly sid?: string;
  /** The OAuth client the change came through: the account API's caller. */
  readonly clientId?: string | null;
}

/**
 * Replace the account's password, with the current one (`account.password.change`).
 * The caller has checked a fresh sign-in with the strongest factor, and the
 * page its form's CSRF token.
 *
 * The current password is checked as a sign-in checks it, reserved on the
 * account's failure ladder first, so a wrong one counts. The new one meets
 * the realm's one password policy (#634) and its breach list. In one
 * transaction the new hash is written, over the hash just checked only (a
 * reset that committed meanwhile replaced it, and the change writes
 * nothing), the account's `update_password` action cleared, its unredeemed
 * codes and refresh tokens ended (a refresh family names no session, so none
 * of them is the changing session's to keep) and `user.password_changed`
 * recorded. Then every sign-in in progress that began before ends at its next
 * round (`recordPasswordChange`), every other browser session ends, the
 * changing session ({@link PasswordChanger.sid}) stays, and the "password
 * changed" notice goes out.
 */
export async function changePassword(
  fastify: FastifyInstance,
  request: FastifyRequest,
  changer: PasswordChanger,
  input: { readonly current: string; readonly next: string; readonly mailer: EngineMailer }
): Promise<PasswordChangeResult> {
  const realm = requestRealm(request);
  const { userId } = changer;
  const clientId = changer.clientId ?? null;
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
  if (!checked.valid) {
    return { kind: 'rejected', messages: [...checked.feedback], reasons: [...checked.reasons] };
  }
  const breach = await fastify.breachedPasswords.check(realm, checked.password);
  if (breach.kind === 'listed') {
    return { kind: 'rejected', messages: [BREACHED_PASSWORD_MESSAGE], reasons: ['breached'] };
  }
  if (breach.kind === 'failed') {
    await emitUserEvent(
      request,
      'urn:qauth:event:user.password_breach_check_failed:v1-rc.0',
      { reason: breach.reason },
      { realmId: realm.id, userId, clientId, actor: 'user' }
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
      { tx, realmId: realm.id, userId, clientId, actor: 'user' }
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
      ...(changer.sid === undefined ? {} : { exceptSid: changer.sid }),
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
