import { relations, sql } from 'drizzle-orm';
import { bigint, boolean, index, jsonb, pgTable, text, uuid, varchar } from 'drizzle-orm/pg-core';

import { oauthClients, users } from './core';
import { codeChallengeMethodEnum } from './enums';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

export const emailVerificationTokens = pgTable(
  'email_verification_tokens',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** SHA-256 hash of the verification token (64 hex characters) */
    tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    used: boolean('used').notNull().default(false),
    usedAt: bigint('used_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_email_verification_tokens_user_id').on(t.userId),
    index('idx_email_verification_tokens_active')
      .on(t.tokenHash, t.expiresAt)
      .where(sql`${t.used} = false`),
    index('idx_email_verification_tokens_expires_at').on(t.expiresAt),
  ]
);

export const authorizationCodes = pgTable(
  'authorization_codes',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    code: varchar('code', { length: 255 }).notNull().unique(),
    oauthClientId: uuid('oauth_client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    redirectUri: text('redirect_uri').notNull(),
    codeChallenge: text('code_challenge').notNull(),
    codeChallengeMethod: codeChallengeMethodEnum('code_challenge_method').notNull().default('S256'),
    nonce: varchar('nonce', { length: 255 }),
    scopes: jsonb('scopes').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    state: varchar('state', { length: 255 }),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    used: boolean('used').notNull().default(false),
    usedAt: bigint('used_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_authorization_codes_active')
      .on(t.code, t.expiresAt)
      .where(sql`${t.used} = false`),
    index('idx_authorization_codes_expires_at').on(t.expiresAt),
    index('idx_authorization_codes_user_id').on(t.userId),
    index('idx_authorization_codes_oauth_client_id').on(t.oauthClientId),
  ]
);

export const refreshTokens = pgTable(
  'refresh_tokens',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** SHA-256 hash of the refresh token (64 hex characters) */
    tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    oauthClientId: uuid('oauth_client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    scopes: jsonb('scopes').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    revoked: boolean('revoked').notNull().default(false),
    revokedAt: bigint('revoked_at', { mode: 'number' }),
    revokedReason: varchar('revoked_reason', { length: 255 }),
    /** SHA-256 hash of the previous token for rotation tracking (64 hex characters) */
    previousTokenHash: varchar('previous_token_hash', { length: 64 }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastUsedAt: bigint('last_used_at', { mode: 'number' }),
  },
  (t) => [
    index('idx_refresh_tokens_active')
      .on(t.tokenHash, t.expiresAt)
      .where(sql`${t.revoked} = false`),
    index('idx_refresh_tokens_expires_at').on(t.expiresAt),
    index('idx_refresh_tokens_user_id').on(t.userId),
    index('idx_refresh_tokens_oauth_client_id').on(t.oauthClientId),
    index('idx_refresh_tokens_user_active')
      .on(t.userId, t.expiresAt)
      .where(sql`${t.revoked} = false`),
  ]
);

export const emailVerificationTokensRelations = relations(emailVerificationTokens, ({ one }) => ({
  user: one(users, { fields: [emailVerificationTokens.userId], references: [users.id] }),
}));

export const authorizationCodesRelations = relations(authorizationCodes, ({ one }) => ({
  user: one(users, { fields: [authorizationCodes.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [authorizationCodes.oauthClientId],
    references: [oauthClients.id],
  }),
}));

export const refreshTokensRelations = relations(refreshTokens, ({ one }) => ({
  user: one(users, { fields: [refreshTokens.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [refreshTokens.oauthClientId],
    references: [oauthClients.id],
  }),
}));
