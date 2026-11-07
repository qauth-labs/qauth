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
 * (`UPDATE … WHERE used_at IS NULL`). `confirmed_at` marks the set the
 * person confirmed they saved.
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
    /**
     * The code's lookup digest (#655): a slow hash (Argon2id) of the code
     * under a salt of the realm, the same for the same code, which finds the
     * account by the code alone. Only the sets of an account whose primary identity is a passkey,
     * with no address, carry it: such an account has nothing else to name it
     * by when its passkey is lost. `NULL` for every other set, whose codes are
     * checked only after a first factor named the account. Never the code.
     */
    lookupDigest: text('lookup_digest'),
    /** When the set was issued, in epoch ms on the auth server's clock. */
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    /** When the code was used, in epoch ms; `NULL` while it is unused. */
    usedAt: bigint('used_at', { mode: 'number' }),
    /**
     * When the person confirmed they saved the set, in epoch ms; `NULL` until
     * then. Every row of a set holds the same value. A set nobody confirmed
     * was never seen for sure (a closed tab, a lost answer), so the next
     * sign-in that owes one shows a new set in its place.
     */
    confirmedAt: bigint('confirmed_at', { mode: 'number' }),
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
    // Serves the lookup of an unused code by its digest (#655).
    index('idx_user_recovery_codes_lookup')
      .on(t.realmId, t.lookupDigest)
      .where(sql`${t.lookupDigest} IS NOT NULL AND ${t.usedAt} IS NULL`),
    check('user_recovery_codes_code_hash_not_empty', sql`length(${t.codeHash}) > 0`),
    check(
      'user_recovery_codes_lookup_digest_not_empty',
      sql`${t.lookupDigest} IS NULL OR length(${t.lookupDigest}) > 0`
    ),
    check('user_recovery_codes_created_at_positive', sql`${t.createdAt} > 0`),
    // Not ordered against `created_at`: two servers' clocks may disagree.
    check('user_recovery_codes_used_at_positive', sql`${t.usedAt} IS NULL OR ${t.usedAt} > 0`),
    check(
      'user_recovery_codes_confirmed_at_positive',
      sql`${t.confirmedAt} IS NULL OR ${t.confirmedAt} > 0`
    ),
  ]
);

export const userRecoveryCodesRelations = relations(userRecoveryCodes, ({ one }) => ({
  user: one(users, { fields: [userRecoveryCodes.userId], references: [users.id] }),
  realm: one(realms, { fields: [userRecoveryCodes.realmId], references: [realms.id] }),
}));
