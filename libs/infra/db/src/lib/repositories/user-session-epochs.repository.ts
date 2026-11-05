import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, eq, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { users } from '../schema/core';
import { userSessionEpochs } from '../schema/user-session-epochs';

/**
 * The users' session epochs (`user_session_epochs`, #642): the owner's
 * password reset advances one in the transaction that replaces the password,
 * and the browser-session lookup and the sign-in engine read it, through a
 * Redis cache, to end what began before it.
 */

/** A user's session epoch. */
export interface UserSessionEpoch {
  /** How many times it advanced: 1 at the first reset. */
  readonly epoch: number;
  /** When it last advanced, in epoch ms on the auth server's clock. */
  readonly advancedAt: number;
}

/** What {@link UserSessionEpochsRepository.advance} writes. */
export interface AdvanceUserSessionEpochInput {
  /** The realm of the user. The user must belong to it. */
  readonly realmId: string;
  readonly userId: string;
  /** When the epoch advances, in epoch ms on the auth server's clock. */
  readonly at: number;
}

/** The session-epoch repository (#642). */
export interface UserSessionEpochsRepository {
  /** The user's epoch; `undefined` when the realm has no such user, or it was never advanced. */
  find(realmId: string, userId: string, tx?: DbClient): Promise<UserSessionEpoch | undefined>;
  /**
   * Advance the user's epoch by one, in one statement: the first advance
   * writes epoch 1. `advancedAt` never moves back, so a clock behind the last
   * advance's keeps the later time.
   *
   * @throws NotFoundError when the realm has no such user (another realm's
   *   user included), so no caller can advance another realm's user.
   */
  advance(input: AdvanceUserSessionEpochInput, tx?: DbClient): Promise<UserSessionEpoch>;
}

/**
 * Factory for the session-epoch repository (#642).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createUserSessionEpochsRepository(
  defaultDb: DbClient
): UserSessionEpochsRepository {
  return {
    async find(realmId, userId, tx) {
      const [row] = await (tx ?? defaultDb)
        .select({ epoch: userSessionEpochs.epoch, advancedAt: userSessionEpochs.advancedAt })
        .from(userSessionEpochs)
        .where(and(eq(userSessionEpochs.realmId, realmId), eq(userSessionEpochs.userId, userId)))
        .limit(1);
      return row;
    },

    async advance({ realmId, userId, at }, tx) {
      if (!Number.isSafeInteger(at) || at <= 0) {
        throw new RangeError('a session epoch advances at a positive time in epoch ms');
      }
      const invoker = tx ?? defaultDb;
      // The insert's foreign key on (user_id, realm_id) refuses a user of
      // another realm, but as an error that aborts the caller's transaction:
      // read the user first, as `user_required_actions` does.
      const [user] = await invoker
        .select({ id: users.id })
        .from(users)
        .where(and(eq(users.realmId, realmId), eq(users.id, userId)))
        .limit(1);
      if (user === undefined) throw new NotFoundError('User', userId);
      const [row] = await invoker
        .insert(userSessionEpochs)
        .values({ userId, realmId, epoch: 1, advancedAt: at })
        .onConflictDoUpdate({
          target: userSessionEpochs.userId,
          set: {
            epoch: sql`${userSessionEpochs.epoch} + 1`,
            advancedAt: sql`greatest(${userSessionEpochs.advancedAt}, excluded.advanced_at)`,
          },
          // A row is its user's, and a user is of one realm: the guard only
          // keeps a caller's wrong realm from moving it.
          setWhere: eq(userSessionEpochs.realmId, realmId),
        })
        .returning({ epoch: userSessionEpochs.epoch, advancedAt: userSessionEpochs.advancedAt });
      if (row === undefined) throw new NotFoundError('User', userId);
      return row;
    },
  };
}
