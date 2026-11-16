import { PreconditionFailedError } from '@qauth-labs/shared-errors';
import type { FastifyRequest } from 'fastify';

import { emitUserEvent } from '../../helpers/user-events';
import type { AdminTransaction } from '../pipeline';
import {
  type AccountDeletionState,
  accountDeletionStateVersion,
  type DeletableAccount,
  readAccountDeletionState,
  USER_OPERATION_IDS,
} from './operations';

/**
 * AN ADMIN DELETES AN ACCOUNT (`users.delete`, ADR-020 §3, issues #681 and
 * #1090), in the admin handler's transaction, which the call's audit row and
 * its approval's consumption commit in too. In this order:
 *
 * 1. **The lock.** The account row is locked `FOR UPDATE`
 *    (`users_lock_for_deletion`, migration 0080). It is the one lock a
 *    foreign key's key-share check waits for, so from here to the commit
 *    nothing adds a session, a code, a token, a credential or an admin grant
 *    of the account: a sign-in that completes meanwhile waits, and fails once
 *    the account is gone. Every session the cascade removes in step 4 is then
 *    one step 3 ended. An id the realm does not hold (unknown, deleted
 *    already, or another realm's account) locks nothing, and the call ends
 *    here: nothing is changed and no event is written, and the route answers
 *    as for a deletion.
 * 2. **The account again**, as the approval and the classification were made
 *    against: read under the lock, refused once more when it has become a
 *    service account's or an admin's (409), and 412 when its version moved.
 * 3. **Every session ends**, browser and logout-only alike, through the
 *    sessions repository's `revokeForUser`, the path every revocation takes
 *    (#624, #893): the rows are locked in id order and revoked, their
 *    unredeemed codes spent, their registry rows deleted, and one
 *    `user.client_session_ended` notice is written per session and client
 *    that has a back-channel logout URI. The notices are the delivery role's
 *    outbox: they commit with the deletion or not at all, and the delivery
 *    role sends each client its logout token from them, signed for the
 *    session's `sub` and `sid` as they were, so it needs no row of the
 *    account.
 * 4. **The account is deleted** (`users_delete_account`, migration 0080), and
 *    with it, through the schema's cascades, its credentials, recovery codes,
 *    consents, attributes, upstream identities, refresh tokens, codes,
 *    sessions with their registry and family links, required actions and
 *    session epoch. Its access tokens no longer introspect, and
 *    `/oauth/userinfo` refuses them: their `sub` names no account. A browser
 *    that still holds a session cookie finds no session behind it, so the
 *    next authorization request signs in again.
 * 5. **The admin events**, last, since each takes the realm's chain lock
 *    after the rows it changed: one `user.session_revoked` per session ended
 *    (CAEP `session-revoked`), then `user.deleted` (RISC `account-purged`),
 *    the actor the admin or the service account that filed the call.
 *
 * A deadlock with a request of the same account in flight (a code exchange or
 * a refresh-token rotation that holds a row of the account and waits for its
 * key-share lock) aborts one of the two; the call then fails and changes
 * nothing, and its retry deletes the account.
 */

/** What a deletion did. */
export type AccountDeletionOutcome =
  /** The realm holds no account with that id: nothing changed. */
  | { readonly kind: 'absent' }
  | {
      readonly kind: 'deleted';
      readonly userId: string;
      /** The account as it stood under the lock, before the deletion. */
      readonly account: DeletableAccount;
      /** The ids of the sessions it ended, in id order. */
      readonly endedSessions: readonly string[];
    };

/** What {@link deleteAccountOfRealm} acts on and records. */
export interface AccountDeletionInput {
  readonly realmId: string;
  readonly userId: string;
  /** The version of the state the call was classified, and approved, against. */
  readonly stateVersion: string | null;
  /** The admin handler's transaction (`adminTransaction`). */
  readonly tx: AdminTransaction;
  /** The events' actor (`adminEventActor`): the admin, or the service account. */
  readonly actor: { readonly type: 'user' | 'client'; readonly id: string };
}

/**
 * The reason the deletion's sessions are revoked with: an admin's action, as
 * the operator tool's disablement ends them (#893). Their back-channel logout
 * notices carry it.
 */
export const DELETION_SESSION_REASON = 'admin';

/** Delete the account, as the module comment says. */
export async function deleteAccountOfRealm(
  request: FastifyRequest,
  input: AccountDeletionInput
): Promise<AccountDeletionOutcome> {
  const { repositories } = request.server;
  const { realmId, tx, actor } = input;
  const operation = USER_OPERATION_IDS.delete;

  // 1. The lock, or no account: nothing changes.
  if (!(await repositories.users.lockForDeletion(realmId, input.userId, tx))) {
    return { kind: 'absent' };
  }

  // 2. The account under the lock, as it was classified and approved.
  const state: AccountDeletionState = await readAccountDeletionState(
    request.server,
    realmId,
    input.userId,
    tx
  );
  const { userId, account } = state;
  if (account === null) return { kind: 'absent' };
  if (accountDeletionStateVersion(state) !== input.stateVersion) {
    throw new PreconditionFailedError({ operation });
  }

  // 3. Every session ends, each queuing its back-channel logout notices.
  const ended = await repositories.sessions.revokeForUser(
    realmId,
    userId,
    DELETION_SESSION_REASON,
    {},
    tx
  );

  // 4. The account goes, and what hangs off it with it. Its function's own
  // guard refuses a service account's account and an admin's, which the
  // lock and the read above rule out; should it refuse, nothing commits.
  if (!(await repositories.users.deleteAccount(realmId, userId, tx))) {
    throw new PreconditionFailedError({ operation });
  }

  // 5. The admin events, after the rows they record.
  const events = { tx, realmId, userId, actor };
  const endedSessions = ended.map(({ session }) => session.id);
  for (const sid of endedSessions) {
    await emitUserEvent(
      request,
      'urn:qauth:event:user.session_revoked:v1-rc.0',
      { sid, reason: 'account_deleted' },
      events
    );
  }
  await emitUserEvent(request, 'urn:qauth:event:user.deleted:v1-rc.0', {}, events);
  return { kind: 'deleted', userId, account, endedSessions };
}
