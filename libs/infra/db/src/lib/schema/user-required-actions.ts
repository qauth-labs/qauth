import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  index,
  pgTable,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { realms, users } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

/**
 * What a user must do before the next sign-in completes (ADR-017, ADR-020 §3, issue #635).
 * `user_required_actions.action` accepts exactly these; the CHECK
 * `user_required_actions_action_known` is built from this list.
 *
 * - `update_password` — choose a new password. The sign-in engine acts on it
 *   (#635): the person signs in with the old password, then must set a new one
 *   before a session starts.
 * - `setup_mfa` — enrol a second factor (PRO-28). Stored by that work; the
 *   engine does not act on it yet.
 * - `setup_passkey` — register a passkey (PRO-29). As above.
 * - `complete_profile` — fill in missing profile attributes (PRO-29). As above.
 */
export const USER_REQUIRED_ACTIONS = [
  'update_password',
  'setup_mfa',
  'setup_passkey',
  'complete_profile',
] as const;

export type UserRequiredAction = (typeof USER_REQUIRED_ACTIONS)[number];

/**
 * Who asked for a required action; `user_required_actions.source` accepts
 * exactly these (CHECK `user_required_actions_source_known`).
 *
 * - `admin` — an admin asked for it through the admin API.
 * - `user_report` — the person reported "this wasn't me" in the account
 *   console, so the next sign-in must replace the password.
 */
export const USER_REQUIRED_ACTION_SOURCES = ['admin', 'user_report'] as const;

export type UserRequiredActionSource = (typeof USER_REQUIRED_ACTION_SOURCES)[number];

const inList = (values: readonly string[]) =>
  sql.raw(values.map((value) => `'${value}'`).join(', '));

/**
 * The actions a user must still take, one row per user and action (issue
 * #635). Whoever asks for an action writes the row (the admin API, the account
 * console's "this wasn't me"); the sign-in engine reads a user's rows when the
 * credential checks pass, makes the person do what they name, and deletes each
 * row once it is done.
 *
 * Writing an action the user already owes keeps the first row: the unique
 * index `idx_user_required_actions_user_action_unique` makes it idempotent, so
 * `source` and `created_at` say who asked first, and when.
 *
 * The user must belong to `realm_id` (`user_required_actions_user_realm_fk`,
 * as `sessions` does), so no writer can attach an action to another realm's
 * user. Deleting the user or the realm deletes the rows.
 *
 * `action` and `source` are `varchar` with a CHECK rather than Postgres enums,
 * as `ssf_streams.status` is: adding an action later is a CHECK change, not an
 * enum-widening migration.
 */
export const userRequiredActions = pgTable(
  'user_required_actions',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The user who owes the action. Must belong to `realm_id` (`user_required_actions_user_realm_fk`). */
    userId: uuid('user_id').notNull(),
    /** What the user must do. */
    action: varchar('action', { length: 32 }).$type<UserRequiredAction>().notNull(),
    /** Who asked for it. */
    source: varchar('source', { length: 16 }).$type<UserRequiredActionSource>().notNull(),
    /** When the action was first asked for, in epoch ms. */
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    foreignKey({
      columns: [t.userId, t.realmId],
      foreignColumns: [users.id, users.realmId],
      name: 'user_required_actions_user_realm_fk',
    }).onDelete('cascade'),
    // One row per user and action; also serves a user's lookup and the user
    // foreign key's cascade.
    uniqueIndex('idx_user_required_actions_user_action_unique').on(t.userId, t.action),
    // Serves the realm foreign key's cascade.
    index('idx_user_required_actions_realm_id').on(t.realmId),
    check(
      'user_required_actions_action_known',
      sql`${t.action} in (${inList(USER_REQUIRED_ACTIONS)})`
    ),
    check(
      'user_required_actions_source_known',
      sql`${t.source} in (${inList(USER_REQUIRED_ACTION_SOURCES)})`
    ),
  ]
);

export const userRequiredActionsRelations = relations(userRequiredActions, ({ one }) => ({
  user: one(users, { fields: [userRequiredActions.userId], references: [users.id] }),
  realm: one(realms, { fields: [userRequiredActions.realmId], references: [realms.id] }),
}));
