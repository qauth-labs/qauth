import type { InferInsertModel, InferSelectModel } from 'drizzle-orm';

import type { oauthConsents } from '../lib/schema/consents';
import type { oauthClients } from '../lib/schema/core';
import type {
  authorizationCodes,
  emailVerificationTokens,
  refreshTokens,
} from '../lib/schema/tokens';
import type { DbClient } from './database';

/**
 * OAuth client types
 */
export type OAuthClient = InferSelectModel<typeof oauthClients>;
export type NewOAuthClient = InferInsertModel<typeof oauthClients>;
export type UpdateOAuthClient = Partial<Omit<NewOAuthClient, 'id' | 'createdAt' | 'realmId'>> & {
  updatedAt?: number;
};

/**
 * Email verification token types
 */
export type EmailVerificationToken = InferSelectModel<typeof emailVerificationTokens>;
export type NewEmailVerificationToken = InferInsertModel<typeof emailVerificationTokens>;

/**
 * Refresh token types inferred from schema
 */
export type RefreshToken = InferSelectModel<typeof refreshTokens>;
export type NewRefreshToken = InferInsertModel<typeof refreshTokens>;

/**
 * Authorization code types inferred from schema
 */
export type AuthorizationCode = InferSelectModel<typeof authorizationCodes>;
export type NewAuthorizationCode = InferInsertModel<typeof authorizationCodes>;

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
 * OAuth clients repository interface extending BaseRepository with additional methods
 */
export interface OAuthClientsRepository extends BaseRepository<
  OAuthClient,
  NewOAuthClient,
  UpdateOAuthClient
> {
  /**
   * Find an OAuth client by client ID within a realm
   */
  findByClientId(
    realmId: string,
    clientId: string,
    tx?: DbClient
  ): Promise<OAuthClient | undefined>;
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

/**
 * Refresh tokens repository interface
 */
export interface RefreshTokensRepository {
  /**
   * Create a new refresh token
   */
  create(data: NewRefreshToken, tx?: DbClient): Promise<RefreshToken>;
  /**
   * Find a token by its token hash
   * Only returns tokens that are not revoked and not expired
   */
  findByTokenHash(tokenHash: string, tx?: DbClient): Promise<RefreshToken | undefined>;
  /**
   * Find all active tokens for a user
   * Returns tokens that are not revoked and not expired
   */
  findByUserId(userId: string, tx?: DbClient): Promise<RefreshToken[]>;
  /**
   * Revoke a token by ID
   * Sets revoked=true, revokedAt=now, and optional revocation reason
   */
  revoke(id: string, reason?: string, tx?: DbClient): Promise<RefreshToken>;
  /**
   * Revoke all active tokens for a user
   * Useful for "logout all sessions" functionality
   */
  revokeAllForUser(userId: string, reason?: string, tx?: DbClient): Promise<void>;
  /**
   * Delete expired tokens
   * Returns count of deleted tokens
   */
  deleteExpired(tx?: DbClient): Promise<number>;
}

/**
 * OAuth consent types
 */
export type OAuthConsent = InferSelectModel<typeof oauthConsents>;
export type NewOAuthConsent = InferInsertModel<typeof oauthConsents>;

/**
 * OAuth consents repository interface.
 *
 * Consents are scoped to (userId, oauthClientId). A single active
 * (not revoked) row exists per pair; re-consent merges scopes into the same
 * row. Revocation sets `revokedAt` rather than deleting, so history is kept.
 */
export interface OAuthConsentsRepository {
  /** Create a consent row (insert). Caller is responsible for uniqueness. */
  create(data: NewOAuthConsent, tx?: DbClient): Promise<OAuthConsent>;
  /** Fetch the active (non-revoked) consent for a (user, client) pair. */
  findActive(
    userId: string,
    oauthClientId: string,
    tx?: DbClient
  ): Promise<OAuthConsent | undefined>;
  /** List all active consents for a user, joined to client metadata (revocation UI). */
  listActiveForUser(userId: string, tx?: DbClient): Promise<OAuthConsent[]>;
  /**
   * Grant/update consent for (user, client).
   *
   * If an active row exists, its `scopes` array is replaced with the union
   * of old ∪ new and `grantedAt` is refreshed. Otherwise a new row is
   * inserted.
   */
  upsertGrant(
    userId: string,
    oauthClientId: string,
    realmId: string,
    scopes: string[],
    tx?: DbClient
  ): Promise<OAuthConsent>;
  /** Revoke a consent row by id (owner must be checked by caller). */
  revoke(id: string, tx?: DbClient): Promise<OAuthConsent>;
}

/**
 * Authorization codes repository interface
 */
export interface AuthorizationCodesRepository {
  /**
   * Create a new authorization code
   */
  create(data: NewAuthorizationCode, tx?: DbClient): Promise<AuthorizationCode>;
  /**
   * Find an authorization code by its code value
   * Only returns codes that are not used and not expired
   */
  findByCode(code: string, tx?: DbClient): Promise<AuthorizationCode | undefined>;
  /**
   * Mark a code as used
   * Sets used=true and usedAt=now
   */
  markUsed(id: string, tx?: DbClient): Promise<AuthorizationCode>;
  /**
   * Invalidate all active codes for a user
   * Useful for security events (password change, account compromise)
   */
  invalidateForUser(userId: string, tx?: DbClient): Promise<number>;
  /**
   * Delete expired codes
   * Returns count of deleted codes
   */
  deleteExpired(tx?: DbClient): Promise<number>;
}
