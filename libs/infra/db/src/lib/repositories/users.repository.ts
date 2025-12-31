import {
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth/shared-errors';
import { normalizeEmail } from '@qauth/shared-validation';
import { and, eq, InferInsertModel, InferSelectModel } from 'drizzle-orm';

import { DbClient } from '../db';
import { users } from '../schema/core';
import { BaseRepository } from './base.repository';

export type User = InferSelectModel<typeof users>;
export type NewUser = InferInsertModel<typeof users>;
export type UpdateUser = Partial<Omit<NewUser, 'id' | 'createdAt' | 'realmId'>> & {
  updatedAt?: number;
};

/**
 * Users repository interface extending BaseRepository with additional methods
 */
export interface UsersRepository extends BaseRepository<User, NewUser, UpdateUser> {
  /**
   * Find a user by email (case-insensitive lookup)
   */
  findByEmail(realmId: string, email: string, tx?: DbClient): Promise<User | undefined>;
  /**
   * Find a user by normalized email
   */
  findByEmailNormalized(
    realmId: string,
    emailNormalized: string,
    tx?: DbClient
  ): Promise<User | undefined>;
  /**
   * Update the last login timestamp for a user
   */
  updateLastLogin(id: string, tx?: DbClient): Promise<User>;
  /**
   * Mark a user's email as verified
   */
  verifyEmail(id: string, tx?: DbClient): Promise<User>;
}

/**
 * Factory function that creates a users repository with CRUD operations
 *
 * @param defaultDb - Database client to use for queries
 * @returns Repository object with CRUD methods implementing BaseRepository
 */
export function createUsersRepository(defaultDb: DbClient): UsersRepository {
  return {
    /**
     * Create a new user
     * Note: Password should be pre-hashed before calling this method
     *
     * @param data - User data to create (emailNormalized will be auto-generated if not provided)
     * @param tx - Optional transaction client
     * @returns Created user
     * @throws UniqueConstraintError if user with same email in realm already exists
     */
    async create(data: NewUser, tx?: DbClient): Promise<User> {
      const invoker = tx ?? defaultDb;
      const userData = {
        ...data,
        emailNormalized: data.emailNormalized ?? normalizeEmail(data.email),
      };

      try {
        const [user] = await invoker.insert(users).values(userData).returning();
        return user;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint =
            extractConstraintName(error) || 'idx_users_realm_email_normalized_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Find a user by ID
     *
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns User if found, undefined otherwise
     */
    async findById(id: string, tx?: DbClient): Promise<User | undefined> {
      const invoker = tx ?? defaultDb;
      const [user] = await invoker.select().from(users).where(eq(users.id, id)).limit(1);
      return user;
    },

    /**
     * Find a user by ID, throwing an error if not found
     *
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns User
     * @throws NotFoundError if user is not found
     */
    async findByIdOrThrow(id: string, tx?: DbClient): Promise<User> {
      const user = await this.findById(id, tx);
      if (!user) {
        throw new NotFoundError('User', id);
      }
      return user;
    },

    /**
     * Find a user by email (case-insensitive lookup)
     * Normalizes the email before querying
     *
     * @param realmId - Realm ID
     * @param email - Email address (will be normalized)
     * @param tx - Optional transaction client
     * @returns User if found, undefined otherwise
     */
    async findByEmail(realmId: string, email: string, tx?: DbClient): Promise<User | undefined> {
      const emailNormalized = normalizeEmail(email);
      return this.findByEmailNormalized(realmId, emailNormalized, tx);
    },

    /**
     * Find a user by normalized email
     *
     * @param realmId - Realm ID
     * @param emailNormalized - Normalized email address
     * @param tx - Optional transaction client
     * @returns User if found, undefined otherwise
     */
    async findByEmailNormalized(
      realmId: string,
      emailNormalized: string,
      tx?: DbClient
    ): Promise<User | undefined> {
      const invoker = tx ?? defaultDb;
      const [user] = await invoker
        .select()
        .from(users)
        .where(and(eq(users.realmId, realmId), eq(users.emailNormalized, emailNormalized)))
        .limit(1);
      return user;
    },

    /**
     * Update a user by ID
     *
     * @param id - User ID
     * @param data - Fields to update (emailNormalized will be auto-updated if email is provided)
     * @param tx - Optional transaction client
     * @returns Updated user
     * @throws NotFoundError if user is not found
     * @throws UniqueConstraintError if email would violate uniqueness
     */
    async update(id: string, data: UpdateUser, tx?: DbClient): Promise<User> {
      const invoker = tx ?? defaultDb;
      const updateData: UpdateUser = {
        ...data,
      };

      // Auto-update emailNormalized if email is being updated
      if (data.email) {
        updateData.emailNormalized = normalizeEmail(data.email);
      }

      // Set updatedAt timestamp
      updateData.updatedAt = data.updatedAt ?? Date.now();

      try {
        const [user] = await invoker
          .update(users)
          .set(updateData)
          .where(eq(users.id, id))
          .returning();

        if (!user) {
          throw new NotFoundError('User', id);
        }

        return user;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint =
            extractConstraintName(error) || 'idx_users_realm_email_normalized_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Update the last login timestamp for a user
     *
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns Updated user
     * @throws NotFoundError if user is not found
     */
    async updateLastLogin(id: string, tx?: DbClient): Promise<User> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [user] = await invoker
        .update(users)
        .set({
          lastLoginAt: now,
          updatedAt: now,
        })
        .where(eq(users.id, id))
        .returning();

      if (!user) {
        throw new NotFoundError('User', id);
      }

      return user;
    },

    /**
     * Mark a user's email as verified
     *
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns Updated user
     * @throws NotFoundError if user is not found
     */
    async verifyEmail(id: string, tx?: DbClient): Promise<User> {
      const invoker = tx ?? defaultDb;
      const now = Date.now();

      const [user] = await invoker
        .update(users)
        .set({
          emailVerified: true,
          emailVerifiedAt: now,
          updatedAt: now,
        })
        .where(eq(users.id, id))
        .returning();

      if (!user) {
        throw new NotFoundError('User', id);
      }

      return user;
    },

    /**
     * Delete a user by ID
     *
     * @param id - User ID
     * @param tx - Optional transaction client
     * @returns True if deleted, false if not found
     */
    async delete(id: string, tx?: DbClient): Promise<boolean> {
      const invoker = tx ?? defaultDb;
      const [user] = await invoker.delete(users).where(eq(users.id, id)).returning();
      return !!user;
    },
  };
}
