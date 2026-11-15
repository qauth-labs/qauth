import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  foreignKey,
  index,
  pgTable,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { oauthClients, realms, users } from './core';
import { EPOCH_MS_NOW } from './sql-helpers';

/** The longest name a service account may have. */
export const SERVICE_ACCOUNT_NAME_MAX_LENGTH = 64;

/**
 * The grammar of a service account's name (issue #522): lower-case ASCII
 * letters and digits in words joined by single hyphens, starting with a
 * letter, such as `ci-realm-import`, as an admin role's name. A name in it
 * hides no look-alike letter or invisible character, so names compare byte for
 * byte, and it prints as it is in an audit row or a log line.
 */
export const SERVICE_ACCOUNT_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;

/** {@link SERVICE_ACCOUNT_NAME_PATTERN} as a POSIX regular expression for the CHECK. */
const SERVICE_ACCOUNT_NAME_SQL = '^[a-z][a-z0-9]*(-[a-z0-9]+)*$';

/**
 * Service accounts (ADR-019 Decision 7, issue #522): automation that reaches
 * the admin API as itself.
 *
 * A service account is a `users` row with no credential, in the operator
 * realm, together with the OAuth client it signs in with. Its admin grants
 * (`admin_grants`) attach to the user row, as a person's do, and the admin
 * API reads them on every request. Its client authenticates with
 * `private_key_jwt` only and gets tokens through `client_credentials`, each
 * bound to a DPoP key: the token's `sub` is the service account's user id.
 * There is no secret and no static key: what the client holds is a private
 * key whose public half the client row lists.
 *
 * - The account has no credential, so it cannot sign in anywhere, and no
 *   credential added later becomes its primary identity (migration 0068).
 * - It never approves a security operation and never counts as one of two
 *   admins: every approval of its requests comes from a human admin.
 * - `enabled = false` refuses its token at the token endpoint and every
 *   admin call from the next request on, whatever token it holds.
 *
 * Who writes it: the host's `service-accounts` command and, later, the admin
 * API's `serviceAccounts.create` (#679). No service role writes it; every role
 * that authenticates a client or an admin call reads it.
 *
 * The account is the operator realm's: the writer refuses any other realm,
 * and the token endpoint and the admin API refuse a service account whose
 * realm is no longer the operator realm. The user foreign key names the realm
 * too (`service_accounts_user_realm_fk`), so the account and the row can never
 * be of two realms. The client is checked to be of the same realm when the
 * row is written; its id is unique here, so one client is one service
 * account's.
 */
export const serviceAccounts = pgTable(
  'service_accounts',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** The realm the account lives in: the operator realm. */
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** Unique in its realm, in the grammar of {@link SERVICE_ACCOUNT_NAME_PATTERN}. */
    name: varchar('name', { length: SERVICE_ACCOUNT_NAME_MAX_LENGTH }).notNull(),
    /** The account: a user of the realm with no credential. Its admin grants name it. */
    userId: uuid('user_id').notNull(),
    /** The OAuth client the account signs in with (`oauth_clients.id`). */
    clientId: uuid('client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    /** A disabled service account gets no token and makes no admin call. */
    enabled: boolean('enabled').notNull().default(true),
    /**
     * The admin who created it. NULL when the host's command or QAuth itself
     * created it, or when that admin's account was deleted since; the admin
     * audit log keeps who it was.
     */
    createdBy: uuid('created_by').references(() => users.id, { onDelete: 'set null' }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    unique('service_accounts_realm_name_unique').on(t.realmId, t.name),
    unique('service_accounts_user_id_unique').on(t.userId),
    unique('service_accounts_client_id_unique').on(t.clientId),
    // The account belongs to the row's realm (`users_id_realm_id_unique`).
    foreignKey({
      columns: [t.userId, t.realmId],
      foreignColumns: [users.id, users.realmId],
      name: 'service_accounts_user_realm_fk',
    }).onDelete('cascade'),
    index('idx_service_accounts_created_by').on(t.createdBy),
    check(
      'service_accounts_name_grammar',
      sql`${t.name} ~ ${sql.raw(`'${SERVICE_ACCOUNT_NAME_SQL}'`)}`
    ),
  ]
);
