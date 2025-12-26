import {
  extractConstraintName,
  isUniqueConstraintError,
  NotFoundError,
  UniqueConstraintError,
} from '@qauth/errors';
import { eq, InferInsertModel, InferSelectModel } from 'drizzle-orm';

import { db, DbClient } from '../db';
import { realms } from '../schema/core';
import { BaseRepository } from './base.repository';

export type Realm = InferSelectModel<typeof realms>;
export type NewRealm = InferInsertModel<typeof realms>;
export type UpdateRealm = Partial<Omit<NewRealm, 'id' | 'createdAt'>> & {
  updatedAt?: number;
};

/**
 * Realms repository interface extending BaseRepository with additional methods
 */
export interface RealmsRepository extends BaseRepository<Realm, NewRealm, UpdateRealm> {
  /**
   * Find a realm by name
   */
  findByName(name: string, tx?: DbClient): Promise<Realm | undefined>;
}

/**
 * Factory function that creates a realms repository with CRUD operations
 *
 * @param defaultDb - Default database client to use (defaults to main db instance)
 * @returns Repository object with CRUD methods implementing BaseRepository
 */
export function createRealmsRepository(defaultDb: DbClient = db): RealmsRepository {
  return {
    /**
     * Create a new realm
     *
     * @param data - Realm data to create
     * @param tx - Optional transaction client
     * @returns Created realm
     * @throws UniqueConstraintError if realm name already exists
     */
    async create(data: NewRealm, tx?: DbClient): Promise<Realm> {
      const invoker = tx ?? defaultDb;
      try {
        const [realm] = await invoker.insert(realms).values(data).returning();
        return realm;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint = extractConstraintName(error) || 'realms_name_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Find a realm by ID
     *
     * @param id - Realm ID
     * @param tx - Optional transaction client
     * @returns Realm if found, undefined otherwise
     */
    async findById(id: string, tx?: DbClient): Promise<Realm | undefined> {
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker.select().from(realms).where(eq(realms.id, id)).limit(1);
      return realm;
    },

    /**
     * Find a realm by ID, throwing an error if not found
     *
     * @param id - Realm ID
     * @param tx - Optional transaction client
     * @returns Realm
     * @throws NotFoundError if realm is not found
     */
    async findByIdOrThrow(id: string, tx?: DbClient): Promise<Realm> {
      const realm = await this.findById(id, tx);
      if (!realm) {
        throw new NotFoundError('Realm', id);
      }
      return realm;
    },

    /**
     * Find a realm by name
     *
     * @param name - Realm name
     * @param tx - Optional transaction client
     * @returns Realm if found, undefined otherwise
     */
    async findByName(name: string, tx?: DbClient): Promise<Realm | undefined> {
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker.select().from(realms).where(eq(realms.name, name)).limit(1);
      return realm;
    },

    /**
     * Update a realm by ID
     *
     * @param id - Realm ID
     * @param data - Fields to update
     * @param tx - Optional transaction client
     * @returns Updated realm
     * @throws NotFoundError if realm is not found
     * @throws UniqueConstraintError if realm name would violate uniqueness
     */
    async update(id: string, data: UpdateRealm, tx?: DbClient): Promise<Realm> {
      const invoker = tx ?? defaultDb;
      const updateData = {
        ...data,
        updatedAt: data.updatedAt ?? Date.now(),
      };

      try {
        const [realm] = await invoker
          .update(realms)
          .set(updateData)
          .where(eq(realms.id, id))
          .returning();

        if (!realm) {
          throw new NotFoundError('Realm', id);
        }

        return realm;
      } catch (error) {
        if (isUniqueConstraintError(error)) {
          const constraint = extractConstraintName(error) || 'realms_name_unique';
          throw new UniqueConstraintError(constraint, error);
        }
        throw error;
      }
    },

    /**
     * Delete a realm by ID
     *
     * @param id - Realm ID
     * @param tx - Optional transaction client
     * @returns True if deleted, false if not found
     */
    async delete(id: string, tx?: DbClient): Promise<boolean> {
      const invoker = tx ?? defaultDb;
      const [realm] = await invoker.delete(realms).where(eq(realms.id, id)).returning();
      return !!realm;
    },
  };
}

/**
 * Default realms repository instance
 */
export const realmsRepository = createRealmsRepository();
