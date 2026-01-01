import type { InferInsertModel, InferSelectModel } from 'drizzle-orm';

import type { emailVerificationTokens } from '../lib/schema/tokens';
import type { DbClient } from './database';

/**
 * Email verification token types
 */
export type EmailVerificationToken = InferSelectModel<typeof emailVerificationTokens>;
export type NewEmailVerificationToken = InferInsertModel<typeof emailVerificationTokens>;

/**
 * Base repository interface for common CRUD operations
 * This provides a consistent interface for all repositories
 * Implementations should follow this pattern to reduce code duplication
 */
export interface BaseRepository<TSelect, TInsert, TUpdate> {
  /** Create a new entity */
  create(data: TInsert, tx?: DbClient): Promise<TSelect>;
  /** Find an entity by ID @returns Entity if found, undefined otherwise */
  findById(id: string, tx?: DbClient): Promise<TSelect | undefined>;
  /** Find an entity by ID, throwing an error if not found @throws NotFoundError if entity is not found */
  findByIdOrThrow(id: string, tx?: DbClient): Promise<TSelect>;
  /** Update an entity by ID @throws NotFoundError if entity is not found */
  update(id: string, data: TUpdate, tx?: DbClient): Promise<TSelect>;
  /** Delete an entity by ID @returns True if deleted, false if not found */
  delete(id: string, tx?: DbClient): Promise<boolean>;
}

/**
 * Email verification tokens repository interface
 */
export interface EmailVerificationTokensRepository {
  /**
   * Create a new email verification token
   */
  create(data: NewEmailVerificationToken, tx?: DbClient): Promise<EmailVerificationToken>;
  /**
   * Find a token by its token hash
   */
  findByTokenHash(tokenHash: string, tx?: DbClient): Promise<EmailVerificationToken | undefined>;
  /**
   * Mark a token as used
   */
  markUsed(id: string, tx?: DbClient): Promise<EmailVerificationToken>;
  /**
   * Invalidate all active tokens for a user
   */
  invalidateUserTokens(userId: string, tx?: DbClient): Promise<number>;
  /**
   * Delete expired tokens
   */
  deleteExpired(tx?: DbClient): Promise<EmailVerificationToken[]>;
}
