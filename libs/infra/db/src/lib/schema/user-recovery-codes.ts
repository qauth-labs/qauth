import { relations, sql } from 'drizzle-orm';
import { bigint, check, foreignKey, index, pgTable, text, uuid } from 'drizzle-orm/pg-core';

import { realms, users } from './core';

/**
 * Each account's recovery codes (#649; ADR-017 Decision 8, ADR-018 §3): one
 * row per code of the account's current set, 10 to a set. A code is 80 bits
 * from a CSPRNG, shown to the person once and never stored: the row holds only
 * its salted hash from the password hasher (Argon2id, the PHC string). On the
 * hosted pages a code stands in for a lost factor after the first factor, and
 * is used once: `used_at` is set by the one write that takes it
 * (`UPDATE … WHERE used_at IS NULL`).
 *
 * A new set replaces the old one in one transaction, so every code of the old
 * set stops working. The user must belong to `realm_id`
 * (`user_recovery_codes_user_realm_fk`, as `user_session_epochs` does), and
 * deleting the user or the realm deletes the rows.
 *
 * Its own table, not a `user_credentials` row: a set is not an
 * authenticator, adds no `amr` value, and its rows are written and taken one
 * code at a time.
 */
export const userRecoveryCodes = pgTable(
  'user_recovery_codes',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The account the code is for. Must belong to `realm_id` (`user_recovery_codes_user_realm_fk`). */
    userId: uuid('user_id').notNull(),
    /** The code's salted hash from the password hasher: never the code. */
    codeHash: text('code_hash').notNull(),
    /** When the set was issued, in epoch ms on the auth server's clock. */
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    /** When the code was used, in epoch ms; `NULL` while it is unused. */
    usedAt: bigint('used_at', { mode: 'number' }),
  },
  (t) => [
    foreignKey({
      columns: [t.userId, t.realmId],
      foreignColumns: [users.id, users.realmId],
      name: 'user_recovery_codes_user_realm_fk',
    }).onDelete('cascade'),
    // Serves an account's lookup and the user foreign key's cascade.
    index('idx_user_recovery_codes_user_realm').on(t.userId, t.realmId),
    // Serves the realm foreign key's cascade.
    index('idx_user_recovery_codes_realm_id').on(t.realmId),
    check('user_recovery_codes_code_hash_not_empty', sql`length(${t.codeHash}) > 0`),
    check('user_recovery_codes_created_at_positive', sql`${t.createdAt} > 0`),
    // Not ordered against `created_at`: two servers' clocks may disagree.
    check('user_recovery_codes_used_at_positive', sql`${t.usedAt} IS NULL OR ${t.usedAt} > 0`),
  ]
);

export const userRecoveryCodesRelations = relations(userRecoveryCodes, ({ one }) => ({
  user: one(users, { fields: [userRecoveryCodes.userId], references: [users.id] }),
  realm: one(realms, { fields: [userRecoveryCodes.realmId], references: [realms.id] }),
}));
