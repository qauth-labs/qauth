import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, eq, isNull, sql } from 'drizzle-orm';

import type { DbClient } from '../../types';
import { users } from '../schema/core';
import { userRecoveryCodes } from '../schema/user-recovery-codes';

/**
 * The accounts' recovery codes (`user_recovery_codes`, #649): the sign-in
 * engine reads an account's unused codes and takes one at sign-in, and
 * issuing a set (the first enrolment of a second factor, a regeneration)
 * replaces the account's set. A row holds only a code's salted hash.
 */

/** What an account holds of recovery codes. */
export interface UserRecoveryCodeStatus {
  /** Whether the account holds a set, used up or not. */
  readonly issued: boolean;
  /** How many of its codes are unused. */
  readonly unused: number;
}

/** One unused code of an account's set. */
export interface UnusedRecoveryCode {
  readonly id: string;
  /** The code's salted hash from the password hasher. */
  readonly codeHash: string;
}

/** What {@link UserRecoveryCodesRepository.replaceSet} writes. */
export interface ReplaceRecoveryCodeSetInput {
  /** The realm of the user. The user must belong to it. */
  readonly realmId: string;
  readonly userId: string;
  /** The new set's hashes, one row each. */
  readonly codeHashes: readonly string[];
  /** When the set is issued, in epoch ms on the auth server's clock. */
  readonly createdAt: number;
}

/** What {@link UserRecoveryCodesRepository.markUsed} writes. */
export interface MarkRecoveryCodeUsedInput {
  readonly realmId: string;
  readonly userId: string;
  /** The code's row. */
  readonly id: string;
  /** When it was used, in epoch ms on the auth server's clock. */
  readonly usedAt: number;
}

/** The recovery-code repository (#649). */
export interface UserRecoveryCodesRepository {
  /** Whether the account holds a set, and how many of its codes are unused. */
  status(realmId: string, userId: string, tx?: DbClient): Promise<UserRecoveryCodeStatus>;
  /** The account's unused codes; none when it holds no set. */
  findUnused(realmId: string, userId: string, tx?: DbClient): Promise<UnusedRecoveryCode[]>;
  /**
   * Replace the account's set, if any, with `codeHashes`, in one transaction
   * (a savepoint inside `tx`): every code of the old set stops working. Two
   * replacements of one account run one after the other (the user's row is
   * locked first), so an account never holds two sets.
   *
   * @throws NotFoundError when the realm has no such user (another realm's
   *   user included), so no caller can write another realm's user's codes.
   */
  replaceSet(input: ReplaceRecoveryCodeSetInput, tx?: DbClient): Promise<void>;
  /**
   * Mark the code `id` of the account used, only while it is unused, in one
   * statement: `true` when this call took it, `false` when it was used
   * already (by another round too) or is not the account's.
   */
  markUsed(input: MarkRecoveryCodeUsedInput, tx?: DbClient): Promise<boolean>;
}

/** A time in epoch ms that a row may hold. */
function checkedTime(at: number, what: string): number {
  if (!Number.isSafeInteger(at) || at <= 0) {
    throw new RangeError(`a recovery code's ${what} is a positive time in epoch ms`);
  }
  return at;
}

/**
 * Factory for the recovery-code repository (#649).
 *
 * @param defaultDb - The database a call without a transaction runs on.
 */
export function createUserRecoveryCodesRepository(
  defaultDb: DbClient
): UserRecoveryCodesRepository {
  const ofAccount = (realmId: string, userId: string) =>
    and(eq(userRecoveryCodes.realmId, realmId), eq(userRecoveryCodes.userId, userId));
  return {
    async status(realmId, userId, tx) {
      const [row] = await (tx ?? defaultDb)
        .select({
          total: sql<number>`count(*)::int`,
          unused: sql<number>`count(*) FILTER (WHERE ${userRecoveryCodes.usedAt} IS NULL)::int`,
        })
        .from(userRecoveryCodes)
        .where(ofAccount(realmId, userId));
      const total = row?.total ?? 0;
      return { issued: total > 0, unused: row?.unused ?? 0 };
    },

    async findUnused(realmId, userId, tx) {
      return (tx ?? defaultDb)
        .select({ id: userRecoveryCodes.id, codeHash: userRecoveryCodes.codeHash })
        .from(userRecoveryCodes)
        .where(and(ofAccount(realmId, userId), isNull(userRecoveryCodes.usedAt)))
        .orderBy(userRecoveryCodes.id);
    },

    async replaceSet({ realmId, userId, codeHashes, createdAt }, tx) {
      checkedTime(createdAt, 'issue time');
      if (codeHashes.length === 0 || codeHashes.some((hash) => hash.length === 0)) {
        throw new RangeError('a recovery-code set holds at least one non-empty hash');
      }
      await (tx ?? defaultDb).transaction(async (inner) => {
        // The user's row is locked first: it holds the user to its realm (the
        // insert's foreign key would refuse another realm's user with an error
        // that aborts the caller's transaction), and it serializes two
        // replacements of one account. `NO KEY UPDATE` lets every insert that
        // only references the user through.
        const [user] = await inner
          .select({ id: users.id })
          .from(users)
          .where(and(eq(users.realmId, realmId), eq(users.id, userId)))
          .limit(1)
          .for('no key update');
        if (user === undefined) throw new NotFoundError('User', userId);
        await inner.delete(userRecoveryCodes).where(ofAccount(realmId, userId));
        await inner
          .insert(userRecoveryCodes)
          .values(codeHashes.map((codeHash) => ({ realmId, userId, codeHash, createdAt })));
      });
    },

    async markUsed({ realmId, userId, id, usedAt }, tx) {
      checkedTime(usedAt, 'use time');
      const taken = await (tx ?? defaultDb)
        .update(userRecoveryCodes)
        .set({ usedAt })
        .where(
          and(
            ofAccount(realmId, userId),
            eq(userRecoveryCodes.id, id),
            isNull(userRecoveryCodes.usedAt)
          )
        )
        .returning({ id: userRecoveryCodes.id });
      return taken.length === 1;
    },
  };
}
