import { relations, sql } from 'drizzle-orm';
import { bigint, boolean, index, pgTable, text, uuid, varchar } from 'drizzle-orm/pg-core';

import { oauthClients, users } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

export const sessions = pgTable(
  'sessions',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid('user_id')
      .notNull()
      .references(() => users.id, { onDelete: 'cascade' }),
    oauthClientId: uuid('oauth_client_id').references(() => oauthClients.id, {
      onDelete: 'set null',
    }),
    accessTokenHash: text('access_token_hash'),
    refreshTokenHash: text('refresh_token_hash'),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    revoked: boolean('revoked').notNull().default(false),
    revokedAt: bigint('revoked_at', { mode: 'number' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    lastActivityAt: bigint('last_activity_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_sessions_user_id').on(t.userId),
    index('idx_sessions_active')
      .on(t.userId, t.expiresAt)
      .where(sql`${t.revoked} = false`),
    index('idx_sessions_expires_at').on(t.expiresAt),
    index('idx_sessions_access_token_hash').on(t.accessTokenHash),
    index('idx_sessions_oauth_client_id').on(t.oauthClientId),
  ]
);

export const sessionsRelations = relations(sessions, ({ one }) => ({
  user: one(users, { fields: [sessions.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [sessions.oauthClientId],
    references: [oauthClients.id],
  }),
}));
