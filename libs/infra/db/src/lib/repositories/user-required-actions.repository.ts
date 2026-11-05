import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, asc, eq } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { users } from '../schema/core';
import {
  type UserRequiredAction,
  userRequiredActions,
  type UserRequiredActionSource,
} from '../schema/user-required-actions';

/**
 * The actions users must take at their next sign-in (`user_required_actions`,
 * issue #635). The admin API and the account console's "this wasn't me" add
 * them; the sign-in engine reads a user's pending actions and removes each
 * once it is done.
 */

/** What {@link UserRequiredActionsRepository.add} writes. */
export interface AddUserRequiredActionInput {
  /** The realm of the user. The user must belong to it. */
  readonly realmId: string;
  readonly userId: string;
  readonly action: UserRequiredAction;
  /** Who asked for the action. */
  readonly source: UserRequiredActionSource;
}

/** One action a user still owes. */
export interface PendingUserRequiredAction {
  readonly action: UserRequiredAction;
  /** Who asked for it first. */
  readonly source: UserRequiredActionSource;
  /** When it was first asked for, in epoch ms. */
  readonly createdAt: number;
}

/** The required-actions repository (#635). */
export interface UserRequiredActionsRepository {
  /**
   * Require `action` of the user. A user who already owes it keeps the row as
   * it is, with its first `source` and `createdAt`.
   *
   * @returns `true` when a row was written, `false` when the user already
   *   owed the action.
   * @throws NotFoundError when the realm has no such user, so no caller can
   *   attach an action to another realm's user.
   */
  add(input: AddUserRequiredActionInput, tx?: DbClient): Promise<boolean>;
  /** The actions the user of the realm still owes, oldest first. */
  listForUser(realmId: string, userId: string, tx?: DbClient): Promise<PendingUserRequiredAction[]>;
  /**
   * Delete the user's row for `action`, once they have done it.
   *
   * @returns whether a row was deleted.
   */
  remove(
    realmId: string,
    userId: string,
    action: UserRequiredAction,
    tx?: DbClient
  ): Promise<boolean>;
}

/**
 * Factory for the required-actions repository (#635).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createUserRequiredActionsRepository(
  defaultDb: DbClient
): UserRequiredActionsRepository {
  return {
    async add({ realmId, userId, action, source }, tx) {
      const invoker = tx ?? defaultDb;
      // The row's foreign key on (user_id, realm_id) refuses another realm's
      // user too, but as an error that aborts the caller's transaction; this
      // read answers it as an unknown user instead.
      const [user] = await invoker
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.realmId, realmId), eq(users.id, userId)))
        .limit(1);
      if (user === undefined) throw new NotFoundError('User', userId);
      const written = await invoker
        .insert(userRequiredActions)
        .values({ realmId, userId, action, source })
        .onConflictDoNothing({ target: [userRequiredActions.userId, userRequiredActions.action] })
        .returning({ id: userRequiredActions.id });
      return written.length > 0;
    },

    async listForUser(realmId, userId, tx) {
      return (tx ?? defaultDb)
        .select({
          action: userRequiredActions.action,
          source: userRequiredActions.source,
          createdAt: userRequiredActions.createdAt,
        })
        .from(userRequiredActions)
        .where(
          and(eq(userRequiredActions.realmId, realmId), eq(userRequiredActions.userId, userId))
        )
        .orderBy(asc(userRequiredActions.createdAt), asc(userRequiredActions.id));
    },

    async remove(realmId, userId, action, tx) {
      const deleted = await (tx ?? defaultDb)
        .delete(userRequiredActions)
        .where(
          and(
            eq(userRequiredActions.realmId, realmId),
            eq(userRequiredActions.userId, userId),
            eq(userRequiredActions.action, action)
          )
        )
        .returning({ id: userRequiredActions.id });
      return deleted.length > 0;
    },
  };
}
