import { relations, sql } from 'drizzle-orm';
import { bigint, boolean, index, jsonb, pgTable, text, uuid, varchar } from 'drizzle-orm/pg-core';

import { oauthClients, users } from './core';
import { auditEventTypeEnum } from './enums';
import { EPOCH_MS_NOW } from './sql-helpers';

export const auditLogs = pgTable(
  'audit_logs',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    oauthClientId: uuid('oauth_client_id').references(() => oauthClients.id, {
      onDelete: 'set null',
    }),
    event: varchar('event', { length: 100 }).notNull(),
    eventType: auditEventTypeEnum('event_type').notNull(),
    success: boolean('success').notNull().default(true),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    metadata: jsonb('metadata').$type<Record<string, unknown> | null>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    index('idx_audit_logs_user_id').on(t.userId),
    index('idx_audit_logs_oauth_client_id').on(t.oauthClientId),
    index('idx_audit_logs_event_type').on(t.eventType),
    index('idx_audit_logs_event').on(t.event),
    index('idx_audit_logs_created_at').on(t.createdAt),
    index('idx_audit_logs_user_event').on(t.userId, t.event, t.createdAt),
    index('idx_audit_logs_failed')
      .on(t.event, t.createdAt)
      .where(sql`${t.success} = false`),
    index('idx_audit_logs_ip_address').on(t.ipAddress),
  ]
);

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, { fields: [auditLogs.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [auditLogs.oauthClientId],
    references: [oauthClients.id],
  }),
}));
