import { NotFoundError } from '@qauth-labs/shared-errors';
import { and, eq, InferInsertModel, InferSelectModel, sql } from 'drizzle-orm';
import { z } from 'zod';

import type { RealmScopedRepository, UserCredential } from '../../types';
import { DbClient } from '../db';
import { users } from '../schema/core';
import { insertUserCredential } from './user-credentials.repository';

export type User = InferSelectModel<typeof users>;
export type NewUser = InferInsertModel<typeof users>;
/**
 * What an update may change. Not `notValidBefore`: the triggers of migration
 * 0044 set it when the account is disabled (#748), and no caller writes it.
 * Nor an operator's verification (#1052): only
 * {@link UsersRepository.recordOperatorVerification} records it.
 */
export type UpdateUser = Partial<
  Omit<
    NewUser,
    'id' | 'createdAt' | 'realmId' | 'notValidBefore' | 'operatorVerifiedAt' | 'operatorVerifiedBy'
  >
> & {
  updatedAt?: number;
};

/**
 * The textual form of a PostgreSQL `uuid`: any 8-4-4-4-12 hex string.
 *
 * `users.id` is a `uuid` column. A value of any other shape can name no user,
 * and PostgreSQL rejects it as a query parameter (`22P02`, invalid input
 * syntax for type uuid), which surfaces as a 500. Callers pass ids taken from
 * outside the database — an access token's `sub` is a `client_id` on a
 * `client_credentials` token (#754) — so every id-keyed method answers "no such
 * user" for a malformed id before any round-trip.
 *
 * `z.guid()` rather than `z.uuid()`: the latter accepts only RFC 9562 version
 * and variant bits, and would make a row whose id PostgreSQL accepts — an
 * imported or hand-written id — unreachable.
 */
const userIdSchema = z.guid();

/** Whether `id` can be a `users.id` at all. */
function isUserIdShape(id: string): boolean {
  return userIdSchema.safeParse(id).success;
}

/** The row `id` names in `realmId`: a user of another realm matches nothing (#489). */
function userOfRealm(realmId: string, id: string) {
  return and(eq(users.realmId, realmId), eq(users.id, id));
}

/**
 * The credential that creates an account: its primary identity (ADR-015
 * Decision 8 and question 13, #846). The account's realm is the user's.
 */
export interface NewPrimaryCredential {
  /** `user_credentials.provider_type`: `password`, `webauthn`, an upstream type, … */
  readonly providerType: string;
  /** `user_credentials.external_sub`: the method's subject identifier. */
  readonly externalSub: string;
  /** `user_credentials.credential_data`, as the method's provider shapes it; `{}` when absent. */
  readonly credentialData?: Readonly<Record<string, unknown>>;
}

/** A new account: the `users` row and its primary credential. */
export type CreatedUser = User & { readonly primaryCredential: UserCredential };

/**
 * Users repository: realm-scoped CRUD (#489) plus the last-login stamp. A user
 * id is taken from outside the database (a token's `sub`, a code, a session),
 * so every id-keyed method takes the realm the request was resolved to and
 * answers a user of another realm as it answers an unknown id.
 */
export interface UsersRepository extends Omit<
  RealmScopedRepository<User, NewUser, UpdateUser>,
  'create'
> {
  /**
   * Create an account: the `users` row and the credential that creates it,
   * marked as its primary identity (ADR-015 Decision 8, #846), in one
   * transaction. There is no other way to create a user through the
   * repositories, so no account-creation path can leave the mark out.
   *
   * With `tx`, both rows are written in the caller's transaction, and a
   * refusal of the credential leaves it to roll back; without, in a
   * transaction of their own.
   *
   * @throws UniqueConstraintError when the realm already holds the
   * credential's `(provider_type, external_sub)`: nothing is created
   */
  create(data: NewUser, primary: NewPrimaryCredential, tx?: DbClient): Promise<CreatedUser>;
  /**
   * Update the last login timestamp for a user of the realm
   */
  updateLastLogin(realmId: string, id: string, tx?: DbClient): Promise<User>;
  /**
   * Record the admin account `operatorAccountId`'s verification of an
   * enabled account of the realm (`users.verify`, ADR-015 Decision 8,
   * amended 2026-11-08; #1052): `operator_verified_at` takes the time now
   * and `operator_verified_by` `operator:<operatorAccountId>`, through
   * `users_record_operator_verification` (migration 0070), so the admin role
   * that runs it holds no `UPDATE` on `users`. Conditional: an account that
   * is gone, disabled or already verified by an operator is left as it is,
   * and `undefined` returned. Nothing else of the account changes, its
   * credentials and their `email_verified` included. The host's
   * `verify-account` command records its own form as the table's owner
   * (`account-verification/verify-account.ts`).
   */
  recordOperatorVerification(
    realmId: string,
    id: string,
    operatorAccountId: string,
    tx?: DbClient
  ): Promise<RecordedOperatorVerification | undefined>;
}

/** The verification {@link UsersRepository.recordOperatorVerification} wrote. */
export interface RecordedOperatorVerification {
  readonly id: string;
  readonly operatorVerifiedAt: number;
  readonly operatorVerifiedBy: string;
}

/**
 * Factory function that creates a users repository with CRUD operations
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with realm-scoped CRUD methods
 */
export function createUsersRepository(defaultDb: DbClient): UsersRepository {
  return {
    /**
     * Create a new identity anchor with its primary credential (#846). Since
     * #230 the users table carries no email or password fields — credentials
     * go through `user_credentials`, and duplicate registration is guarded
     * by the credentials unique index, not by the users insert.
     *
     * @param data - Identity-anchor data (realmId + optional profile fields)
     * @param primary - The credential that creates the account
     * @param tx - Optional transaction client
     * @returns Created user, with its primary credential
     */
    async create(
      data: NewUser,
      primary: NewPrimaryCredential,
      tx?: DbClient
    ): Promise<CreatedUser> {
      const write = async (invoker: DbClient): Promise<CreatedUser> => {
        const [user] = await invoker.insert(users).values(data).returning();
        const primaryCredential = await insertUserCredential(invoker, {
          userId: user.id,
          realmId: user.realmId,
          providerType: primary.providerType,
          externalSub: primary.externalSub,
          credentialData: { ...primary.credentialData },
          isPrimary: true,
        });
        return { ...user, primaryCredential };
      };
      return tx === undefined ? defaultDb.transaction(write) : write(tx);
    },

    /**
     * Find a user of the realm by ID
     *
     * @param realmId - Realm the request was resolved to
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns User if found, undefined otherwise — including for a user of
     * another realm, and for an id that is not a uuid, which is answered
     * without querying
     */
    async findById(realmId: string, id: string, tx?: DbClient): Promise<User | undefined> {
      if (!isUserIdShape(id)) {
        return undefined;
      }
      const invoker = tx ?? defaultDb;
      const [user] = await invoker.select().from(users).where(userOfRealm(realmId, id)).limit(1);
      return user;
    },

    /**
     * Find a user of the realm by ID, throwing an error if not found
     *
     * @param realmId - Realm the request was resolved to
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns User
     * @throws NotFoundError if the realm has no such user
     */
    async findByIdOrThrow(realmId: string, id: string, tx?: DbClient): Promise<User> {
      const user = await this.findById(realmId, id, tx);
      if (!user) {
        throw new NotFoundError('User', id);
      }
      return user;
    },

    /**
     * Update a user of the realm by ID
     *
     * @param realmId - Realm the request was resolved to
     * @param id - User ID
     * @param data - Fields to update
     * @param tx - Optional transaction client
     * @returns Updated user
     * @throws NotFoundError if the realm has no such user
     */
    async update(realmId: string, id: string, data: UpdateUser, tx?: DbClient): Promise<User> {
      if (!isUserIdShape(id)) {
        throw new NotFoundError('User', id);
      }
      const invoker = tx ?? defaultDb;
      const updateData: UpdateUser = {
        ...data,
      };

      // Set updatedAt timestamp
      updateData.updatedAt = data.updatedAt ?? Date.now();

      const [user] = await invoker
        .update(users)
        .set(updateData)
        .where(userOfRealm(realmId, id))
        .returning();

      if (!user) {
        throw new NotFoundError('User', id);
      }

      return user;
    },

    /**
     * Update the last login timestamp for a user of the realm
     *
     * @param realmId - Realm the request was resolved to
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns Updated user
     * @throws NotFoundError if the realm has no such user
     */
    async updateLastLogin(realmId: string, id: string, tx?: DbClient): Promise<User> {
      if (!isUserIdShape(id)) {
        throw new NotFoundError('User', id);
      }
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [user] = await invoker
        .update(users)
        .set({
          lastLoginAt: now,
          updatedAt: now,
        })
        .where(userOfRealm(realmId, id))
        .returning();

      if (!user) {
        throw new NotFoundError('User', id);
      }

      return user;
    },

    async recordOperatorVerification(
      realmId: string,
      id: string,
      operatorAccountId: string,
      tx?: DbClient
    ): Promise<RecordedOperatorVerification | undefined> {
      if (!isUserIdShape(id) || !isUserIdShape(operatorAccountId)) return undefined;
      const invoker = tx ?? defaultDb;
      const { rows } = await invoker.execute<{
        // node-postgres reads a bigint as a string.
        operator_verified_at: string | number;
        operator_verified_by: string;
      }>(
        sql`select * from "users_record_operator_verification"(${realmId}::uuid, ${id}::uuid, ${operatorAccountId}::uuid, ${Date.now()})`
      );
      const [row] = rows;
      if (row === undefined) return undefined;
      return {
        id,
        operatorVerifiedAt: Number(row.operator_verified_at),
        operatorVerifiedBy: row.operator_verified_by,
      };
    },

    /**
     * Delete a user of the realm by ID
     *
     * @param realmId - Realm the request was resolved to
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns True if deleted, false if the realm has no such user
     */
    async delete(realmId: string, id: string, tx?: DbClient): Promise<boolean> {
      if (!isUserIdShape(id)) {
        return false;
      }
      const invoker = tx ?? defaultDb;
      const [user] = await invoker.delete(users).where(userOfRealm(realmId, id)).returning();
      return !!user;
    },
  };
}
