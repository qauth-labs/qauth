import { sql } from 'drizzle-orm';
import { bigint, check, foreignKey, pgTable, unique, uuid } from 'drizzle-orm/pg-core';

import { realms, users } from './core';
import { bytea } from './sql-helpers';

/**
 * One-time admin enrolments (ADR-019 Decision 7, issue #602).
 *
 * The break-glass command `enrol-admin`, run on a host that holds the
 * database credentials and the KEK, creates an admin account with no
 * password and no credential, its admin grant, and one row here: the hash of
 * a token it prints once, inside an enrolment URL built from the realm row.
 * The Interaction API step that turns the URL into the account's first
 * passkey (#621) redeems the token, once, before it expires.
 *
 * - `token_hash` is SHA-256 over the token's 32 random bytes. The token
 *   itself is never stored, logged or recorded: only whoever holds the URL
 *   holds it.
 * - A token works once: `used_at` is set when it is redeemed, and the trigger
 *   `admin_enrolments_use_once` refuses every other change, so no writer can
 *   make a used token usable again, move its expiry, or move it to another
 *   account. It also refuses a redemption once the database's own clock has
 *   passed `expires_at`, whatever `used_at` the writer hands it.
 * - It expires at `expires_at` (by default an hour after it was made). An
 *   expired token is refused like a used one; the row stays, as the record
 *   of the enrolment.
 * - One enrolment per account: the account was created for it. A token that
 *   expires unused needs a new run of the command, which creates a new
 *   account.
 * - The composite foreign key keeps the account in the row's realm
 *   (`users_id_realm_id_unique`). Deleting the account or the realm removes
 *   the row.
 *
 * Who writes it: the host's command, as the table owner, creates every row.
 * The `web` role, which serves the enrolment step (#621), reads whether a
 * token may still be redeemed and redeems it; it creates and deletes none.
 */
export const adminEnrolments = pgTable(
  'admin_enrolments',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** The realm the account lives in, whose issuer the enrolment URL starts at. */
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The admin account the enrolment registers a first passkey for. */
    userId: uuid('user_id').notNull(),
    /** SHA-256 over the token's 32 bytes. */
    tokenHash: bytea('token_hash').notNull(),
    /** Epoch ms, set by the writer from the clock it computes the expiry with. */
    createdAt: bigint('created_at', { mode: 'number' }).notNull(),
    /** Epoch ms: the token is refused from this moment on. */
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    /** Epoch ms of the redemption; NULL while the token is unused. */
    usedAt: bigint('used_at', { mode: 'number' }),
  },
  (t) => [
    unique('admin_enrolments_token_hash_unique').on(t.tokenHash),
    unique('admin_enrolments_user_id_unique').on(t.userId),
    // The account belongs to the row's realm (`users_id_realm_id_unique`).
    foreignKey({
      columns: [t.userId, t.realmId],
      foreignColumns: [users.id, users.realmId],
      name: 'admin_enrolments_user_realm_fk',
    }).onDelete('cascade'),
    check('admin_enrolments_token_hash_sha256', sql`octet_length(${t.tokenHash}) = 32`),
    check('admin_enrolments_expires_after_created', sql`${t.expiresAt} > ${t.createdAt}`),
    check(
      'admin_enrolments_used_after_created',
      sql`${t.usedAt} IS NULL OR ${t.usedAt} >= ${t.createdAt}`
    ),
  ]
);
