import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, eq, isNotNull, isNull, sql } from 'drizzle-orm';

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
  /** Whether the person confirmed they saved the set: `false` while it holds none. */
  readonly confirmed: boolean;
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
  /**
   * Leave a confirmed set in place, and write nothing: the sign-in engine's
   * own issuance, which must not void a set another sign-in showed and the
   * person confirmed meanwhile. A regeneration leaves it out and replaces
   * whatever the account holds.
   */
  readonly keepConfirmed?: boolean;
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

/** What {@link UserRecoveryCodesRepository.confirmSet} writes. */
export interface ConfirmRecoveryCodeSetInput {
  readonly realmId: string;
  readonly userId: string;
  /** The set the person was shown: the id {@link UserRecoveryCodesRepository.replaceSet} returned. */
  readonly setId: string;
  /** When the person confirmed they saved the set, in epoch ms on the auth server's clock. */
  readonly confirmedAt: number;
}

/** The recovery-code repository (#649). */
export interface UserRecoveryCodesRepository {
  /** Whether the account holds a set, how many of its codes are unused, and whether it is confirmed. */
  status(realmId: string, userId: string, tx?: DbClient): Promise<UserRecoveryCodeStatus>;
  /** The account's unused codes; none when it holds no set. */
  findUnused(realmId: string, userId: string, tx?: DbClient): Promise<UnusedRecoveryCode[]>;
  /**
   * Replace the account's set, if any, with `codeHashes`, in one transaction
   * (a savepoint inside `tx`): every code of the old set stops working. Two
   * replacements of one account, and a replacement and a confirmation, run
   * one after the other (the user's row is locked first), so an account never
   * holds two sets.
   *
   * @returns The new set's id: the id of one of its rows, which only this set
   *   holds, since a replacement deletes every row of the set before. `null`
   *   when `keepConfirmed` met a confirmed set, and nothing was written.
   * @throws NotFoundError when the realm has no such user (another realm's
   *   user included), so no caller can write another realm's user's codes.
   */
  replaceSet(input: ReplaceRecoveryCodeSetInput, tx?: DbClient): Promise<string | null>;
  /**
   * Mark the code `id` of the account used, only while it is unused, in one
   * statement: `true` when this call took it, `false` when it was used
   * already (by another round too) or is not the account's.
   */
  markUsed(input: MarkRecoveryCodeUsedInput, tx?: DbClient): Promise<boolean>;
  /**
   * Mark the set `setId` confirmed, if it is still the account's: the person
   * said they saved it. Under the same lock as a replacement, so a set
   * replaced by another sign-in is never confirmed in place of the one shown.
   * A set confirmed before keeps its time.
   *
   * @returns `true` when `setId` is the account's set (confirmed now or
   *   before); `false` when another set replaced it, or the account holds
   *   none: the codes shown no longer work.
   */
  confirmSet(input: ConfirmRecoveryCodeSetInput, tx?: DbClient): Promise<boolean>;
}

/** A set id is a row's id: a UUID. Anything else names no set. */
const SET_ID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

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
  /**
   * Lock the user's row: it holds the user to its realm (an insert's foreign
   * key would refuse another realm's user with an error that aborts the
   * caller's transaction), and it serializes every replacement and
   * confirmation of one account. `NO KEY UPDATE` lets every insert that only
   * references the user through. `false` when the realm has no such user.
   */
  const lockUser = async (inner: DbClient, realmId: string, userId: string): Promise<boolean> => {
    const [user] = await inner
      .select({ id: users.id })
      .from(users)
      .where(and(eq(users.realmId, realmId), eq(users.id, userId)))
      .limit(1)
      .for('no key update');
    return user !== undefined;
  };
  return {
    async status(realmId, userId, tx) {
      const [row] = await (tx ?? defaultDb)
        .select({
          total: sql<number>`count(*)::int`,
          unused: sql<number>`count(*) FILTER (WHERE ${userRecoveryCodes.usedAt} IS NULL)::int`,
          // Every row of a set holds the same mark; NULL when there is no row.
          confirmed: sql<boolean | null>`bool_and(${userRecoveryCodes.confirmedAt} IS NOT NULL)`,
        })
        .from(userRecoveryCodes)
        .where(ofAccount(realmId, userId));
      const total = row?.total ?? 0;
      return {
        issued: total > 0,
        unused: row?.unused ?? 0,
        confirmed: total > 0 && row?.confirmed === true,
      };
    },

    async findUnused(realmId, userId, tx) {
      return (tx ?? defaultDb)
        .select({ id: userRecoveryCodes.id, codeHash: userRecoveryCodes.codeHash })
        .from(userRecoveryCodes)
        .where(and(ofAccount(realmId, userId), isNull(userRecoveryCodes.usedAt)))
        .orderBy(userRecoveryCodes.id);
    },

    async replaceSet({ realmId, userId, codeHashes, createdAt, keepConfirmed = false }, tx) {
      checkedTime(createdAt, 'issue time');
      if (codeHashes.length === 0 || codeHashes.some((hash) => hash.length === 0)) {
        throw new RangeError('a recovery-code set holds at least one non-empty hash');
      }
      return (tx ?? defaultDb).transaction(async (inner) => {
        if (!(await lockUser(inner, realmId, userId))) throw new NotFoundError('User', userId);
        if (keepConfirmed) {
          const [confirmed] = await inner
            .select({ id: userRecoveryCodes.id })
            .from(userRecoveryCodes)
            .where(and(ofAccount(realmId, userId), isNotNull(userRecoveryCodes.confirmedAt)))
            .limit(1);
          if (confirmed !== undefined) return null;
        }
        await inner.delete(userRecoveryCodes).where(ofAccount(realmId, userId));
        const [first] = await inner
          .insert(userRecoveryCodes)
          .values(codeHashes.map((codeHash) => ({ realmId, userId, codeHash, createdAt })))
          .returning({ id: userRecoveryCodes.id });
        if (first === undefined) throw new Error('a recovery-code set was not written');
        return first.id;
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

    async confirmSet({ realmId, userId, setId, confirmedAt }, tx) {
      checkedTime(confirmedAt, 'confirmation time');
      if (!SET_ID_PATTERN.test(setId)) return false;
      return (tx ?? defaultDb).transaction(async (inner) => {
        if (!(await lockUser(inner, realmId, userId))) return false;
        // A replacement deletes every row of the set before it: a row of the
        // set shown that is still there means the set is the account's.
        const [shown] = await inner
          .select({ id: userRecoveryCodes.id })
          .from(userRecoveryCodes)
          .where(and(ofAccount(realmId, userId), eq(userRecoveryCodes.id, setId)))
          .limit(1);
        if (shown === undefined) return false;
        await inner
          .update(userRecoveryCodes)
          .set({ confirmedAt })
          .where(and(ofAccount(realmId, userId), isNull(userRecoveryCodes.confirmedAt)));
        return true;
      });
    },
  };
}
