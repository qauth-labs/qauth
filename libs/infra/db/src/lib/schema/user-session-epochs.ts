import { relations, sql } from 'drizzle-orm';
import { bigint, check, foreignKey, index, integer, pgTable, uuid } from 'drizzle-orm/pg-core';

import { realms, users } from './core';

/**
 * Each user's session epoch (#642; ADR-017 Decision 8, ADR-019 Decision 3):
 * a counter the owner's password reset advances, and when it last moved.
 * A browser session created before `advanced_at` is absent, and a sign-in
 * transaction that began before it ends, so a reset ends everything the old
 * password opened, whatever cached it.
 *
 * Postgres is the source of truth and Redis caches it. The reset advances the
 * epoch in the transaction that replaces the password, so the two never
 * disagree. A user who was never reset has no row.
 *
 * Its own table, not a `users` column (ADR-002: `users` is a pure identity
 * anchor). The user must belong to `realm_id`
 * (`user_session_epochs_user_realm_fk`, as `user_required_actions` does), and
 * deleting the user or the realm deletes the row.
 */
export const userSessionEpochs = pgTable(
  'user_session_epochs',
  {
    /** The user: one row each. Must belong to `realm_id` (`user_session_epochs_user_realm_fk`). */
    userId: uuid('user_id').primaryKey(),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** How many times the epoch advanced: 1 at the first reset. */
    epoch: integer('epoch').notNull(),
    /**
     * When the epoch last advanced, in epoch ms, on the auth server's clock (a
     * session's `created_at` is too): every session and transaction that began
     * before it is over.
     */
    advancedAt: bigint('advanced_at', { mode: 'number' }).notNull(),
  },
  (t) => [
    foreignKey({
      columns: [t.userId, t.realmId],
      foreignColumns: [users.id, users.realmId],
      name: 'user_session_epochs_user_realm_fk',
    }).onDelete('cascade'),
    // Serves the realm foreign key's cascade.
    index('idx_user_session_epochs_realm_id').on(t.realmId),
    check('user_session_epochs_epoch_positive', sql`${t.epoch} > 0`),
    check('user_session_epochs_advanced_at_positive', sql`${t.advancedAt} > 0`),
  ]
);

export const userSessionEpochsRelations = relations(userSessionEpochs, ({ one }) => ({
  user: one(users, { fields: [userSessionEpochs.userId], references: [users.id] }),
  realm: one(realms, { fields: [userSessionEpochs.realmId], references: [realms.id] }),
}));
