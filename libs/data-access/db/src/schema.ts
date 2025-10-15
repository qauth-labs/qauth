// Database schema definitions using Drizzle ORM
// OAuth 2.1/OIDC compliant tables with proper indexing and constraints

import {
  boolean,
  index,
  jsonb,
  pgTable,
  text,
  timestamp,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

// =============================================================================
// Users Table
// =============================================================================

/**
 * Users table - stores user accounts and authentication data
 *
 * Design decisions:
 * - UUID primary key: Better for distributed systems, no sequential leaks
 * - Email unique constraint: Fast login queries, prevents duplicates
 * - Argon2id password hash: Post-quantum secure, OWASP recommended
 * - Email verification: Required for production OAuth flows
 */
export const users = pgTable('users', {
  id: uuid('id').primaryKey().defaultRandom(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  passwordHash: text('password_hash').notNull(),
  emailVerified: boolean('email_verified').notNull().default(false),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// Index for fast email lookups during login
export const usersEmailIndex = index('users_email_idx').on(users.email);

// =============================================================================
// OAuth Clients Table
// =============================================================================

/**
 * OAuth clients table - stores registered applications
 *
 * Design decisions:
 * - clientId unique: Required by OAuth spec, indexed for fast lookups
 * - clientSecretHash: Never store secrets in plain text
 * - redirectUris as JSONB: PostgreSQL native array support, efficient queries
 * - developerId foreign key: Links to user who owns the client
 */
export const oauthClients = pgTable('oauth_clients', {
  id: uuid('id').primaryKey().defaultRandom(),
  clientId: varchar('client_id', { length: 255 }).notNull().unique(),
  clientSecretHash: text('client_secret_hash').notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  description: text('description'),
  redirectUris: jsonb('redirect_uris').notNull().$type<string[]>(),
  developerId: uuid('developer_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// Index for fast client lookups during OAuth flows
export const oauthClientsClientIdIndex = index('oauth_clients_client_id_idx').on(
  oauthClients.clientId
);
export const oauthClientsDeveloperIdIndex = index('oauth_clients_developer_id_idx').on(
  oauthClients.developerId
);

// =============================================================================
// Authorization Codes Table (OAuth 2.1 PKCE)
// =============================================================================

/**
 * Authorization codes table - stores PKCE authorization codes
 *
 * Design decisions:
 * - PKCE fields mandatory: OAuth 2.1 compliance, prevents code interception
 * - used boolean: Prevents replay attacks, single-use codes
 * - expiresAt with index: Fast cleanup of expired codes
 * - Short TTL: 10 minutes max per OAuth 2.1 spec
 */
export const authorizationCodes = pgTable('authorization_codes', {
  id: uuid('id').primaryKey().defaultRandom(),
  code: varchar('code', { length: 255 }).notNull().unique(),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  redirectUri: text('redirect_uri').notNull(),
  codeChallenge: text('code_challenge').notNull(),
  codeChallengeMethod: varchar('code_challenge_method', { length: 10 }).notNull(),
  scopes: jsonb('scopes').notNull().$type<string[]>(),
  used: boolean('used').notNull().default(false),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// Indexes for fast code lookups and cleanup
export const authorizationCodesCodeIndex = index('authorization_codes_code_idx').on(
  authorizationCodes.code
);
export const authorizationCodesExpiresAtIndex = index('authorization_codes_expires_at_idx').on(
  authorizationCodes.expiresAt
);
export const authorizationCodesClientIdIndex = index('authorization_codes_client_id_idx').on(
  authorizationCodes.clientId
);

// =============================================================================
// Access Tokens Table
// =============================================================================

/**
 * Access tokens table - stores issued access tokens
 *
 * Design decisions:
 * - Short TTL: 15 minutes for security
 * - Scopes tracking: Required for OAuth compliance
 * - Foreign keys: Links to user and client for revocation
 * - No token storage: Store only metadata, tokens are stateless JWTs
 */
export const accessTokens = pgTable('access_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  token: varchar('token', { length: 255 }).notNull().unique(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  scopes: jsonb('scopes').notNull().$type<string[]>(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
});

// Indexes for fast token lookups and cleanup
export const accessTokensTokenIndex = index('access_tokens_token_idx').on(accessTokens.token);
export const accessTokensExpiresAtIndex = index('access_tokens_expires_at_idx').on(
  accessTokens.expiresAt
);
export const accessTokensUserIdIndex = index('access_tokens_user_id_idx').on(accessTokens.userId);

// =============================================================================
// Refresh Tokens Table
// =============================================================================

/**
 * Refresh tokens table - stores refresh tokens for token renewal
 *
 * Design decisions:
 * - revoked boolean: Enables instant logout capability
 * - Longer TTL: 7 days for better UX
 * - Foreign keys: Links to user and client for bulk revocation
 * - updatedAt: Track when token was last used/revoked
 */
export const refreshTokens = pgTable('refresh_tokens', {
  id: uuid('id').primaryKey().defaultRandom(),
  token: varchar('token', { length: 255 }).notNull().unique(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  scopes: jsonb('scopes').notNull().$type<string[]>(),
  revoked: boolean('revoked').notNull().default(false),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
});

// Indexes for fast token lookups and cleanup
export const refreshTokensTokenIndex = index('refresh_tokens_token_idx').on(refreshTokens.token);
export const refreshTokensExpiresAtIndex = index('refresh_tokens_expires_at_idx').on(
  refreshTokens.expiresAt
);
export const refreshTokensUserIdIndex = index('refresh_tokens_user_id_idx').on(
  refreshTokens.userId
);
export const refreshTokensRevokedIndex = index('refresh_tokens_revoked_idx').on(
  refreshTokens.revoked
);

// =============================================================================
// Sessions Table (for Redis-backed session management)
// =============================================================================

/**
 * Sessions table - metadata for Redis-stored sessions
 *
 * Design decisions:
 * - sessionId: Primary key for Redis key lookup
 * - Foreign keys: Links to user and client for session management
 * - lastAccessedAt: Track session activity for cleanup
 * - TTL tracking: Match Redis expiration for consistency
 */
export const sessions = pgTable('sessions', {
  sessionId: varchar('session_id', { length: 255 }).primaryKey(),
  userId: uuid('user_id')
    .notNull()
    .references(() => users.id, { onDelete: 'cascade' }),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
  lastAccessedAt: timestamp('last_accessed_at', { withTimezone: true }).notNull().defaultNow(),
  expiresAt: timestamp('expires_at', { withTimezone: true }).notNull(),
});

// Indexes for session management and cleanup
export const sessionsUserIdIndex = index('sessions_user_id_idx').on(sessions.userId);
export const sessionsExpiresAtIndex = index('sessions_expires_at_idx').on(sessions.expiresAt);
export const sessionsClientIdIndex = index('sessions_client_id_idx').on(sessions.clientId);

// =============================================================================
// Type Exports
// =============================================================================

/**
 * Export types for TypeScript inference
 */
export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;

export type OAuthClient = typeof oauthClients.$inferSelect;
export type NewOAuthClient = typeof oauthClients.$inferInsert;

export type AuthorizationCode = typeof authorizationCodes.$inferSelect;
export type NewAuthorizationCode = typeof authorizationCodes.$inferInsert;

export type AccessToken = typeof accessTokens.$inferSelect;
export type NewAccessToken = typeof accessTokens.$inferInsert;

export type RefreshToken = typeof refreshTokens.$inferSelect;
export type NewRefreshToken = typeof refreshTokens.$inferInsert;

export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
