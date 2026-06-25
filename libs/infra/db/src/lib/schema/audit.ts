import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  index,
  jsonb,
  pgTable,
  text,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { oauthClients, users } from './core';
import { agentModeEnum, auditEventTypeEnum } from './enums';
import { EPOCH_MS_NOW } from './sql-helpers';

export const auditLogs = pgTable(
  'audit_logs',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /**
     * The subject of the action. For agent-attributable entries (ADR-007 §2
     * #186) this is the end-user the agent acted *on behalf of*. Nullable +
     * `set null` so a deleted user does not orphan the historical record.
     */
    userId: uuid('user_id').references(() => users.id, { onDelete: 'set null' }),
    oauthClientId: uuid('oauth_client_id').references(() => oauthClients.id, {
      onDelete: 'set null',
    }),
    event: varchar('event', { length: 100 }).notNull(),
    eventType: auditEventTypeEnum('event_type').notNull(),
    success: boolean('success').notNull().default(true),
    ipAddress: varchar('ip_address', { length: 45 }),
    userAgent: text('user_agent'),
    /**
     * Per-agent action audit (ADR-007 §2, #186). Denormalized `client_id`
     * STRING of the agent that performed the action on behalf of `userId`.
     * Stored as a string (not the `oauth_clients.id` FK) so the attribution
     * survives deletion of the client row (the FK `oauthClientId` is
     * `set null` on delete). Null for ordinary, non-delegated entries.
     * NEVER a token or secret — only the public client identifier.
     */
    actorClientId: varchar('actor_client_id', { length: 255 }),
    /**
     * The RFC 8693 `act` delegation chain flattened to the ordered list of
     * actor `client_id`s — index 0 is the most recent (outermost) actor, each
     * following entry a prior actor. Turns the in-token chain into an
     * accountable, queryable record. Contains ONLY public client identifiers;
     * never any token, secret, or subject material. Null when not delegated.
     */
    delegationChain: jsonb('delegation_chain').$type<string[] | null>(),
    /**
     * The agent scope mode (`readonly` | `admin` | `exec`) granted for this
     * action, when the operation was gated by an agent scope mode (#184).
     * Null when the action carries no agent-mode scope.
     */
    scopeMode: agentModeEnum('scope_mode'),
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
    // "Agent activity" queries: which actions did this agent take, newest
    // first. Partial — only agent-attributed rows carry an actorClientId.
    index('idx_audit_logs_actor_client_id')
      .on(t.actorClientId, t.createdAt)
      .where(sql`${t.actorClientId} IS NOT NULL`),
    // Defensive: the delegation chain is a JSON array of client_id strings.
    // Mirrors the `oauth_clients_audience_is_array` check so a malformed
    // (non-array) value cannot be persisted even if a future caller bypasses
    // the typed `$type<string[]>()` helper.
    check(
      'audit_logs_delegation_chain_is_array',
      sql`${t.delegationChain} IS NULL OR jsonb_typeof(${t.delegationChain}) = 'array'`
    ),
  ]
);

export const auditLogsRelations = relations(auditLogs, ({ one }) => ({
  user: one(users, { fields: [auditLogs.userId], references: [users.id] }),
  oauthClient: one(oauthClients, {
    fields: [auditLogs.oauthClientId],
    references: [oauthClients.id],
  }),
}));
