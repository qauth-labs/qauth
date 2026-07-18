import { NotFoundError } from '@qauth-labs/shared-errors';
import { eq, InferInsertModel, InferSelectModel } from 'drizzle-orm';

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
   * Update the last login timestamp for a user
   */
  updateLastLogin(id: string, tx?: DbClient): Promise<User>;
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
     * Create a new identity anchor. Since #230 the users table carries no
     * email or password fields — credentials go through `user_credentials`,
     * and duplicate registration is guarded by the credentials unique index,
     * not by this insert.
     *
     * @param data - Identity-anchor data (realmId + optional profile fields)
     * @param tx - Optional transaction client
     * @returns Created user
     */
    async create(data: NewUser, tx?: DbClient): Promise<User> {
      const invoker = tx ?? defaultDb;
      const [user] = await invoker.insert(users).values(data).returning();
      return user;
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
     * Update a user by ID
     *
     * @param id - User ID
     * @param data - Fields to update
     * @param tx - Optional transaction client
     * @returns Updated user
     * @throws NotFoundError if user is not found
     */
    async update(id: string, data: UpdateUser, tx?: DbClient): Promise<User> {
      const invoker = tx ?? defaultDb;
      const updateData: UpdateUser = {
        ...data,
      };

      // Set updatedAt timestamp
      updateData.updatedAt = data.updatedAt ?? Date.now();

      const [user] = await invoker
        .update(users)
        .set(updateData)
        .where(eq(users.id, id))
        .returning();

      if (!user) {
        throw new NotFoundError('User', id);
      }

      return user;
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
