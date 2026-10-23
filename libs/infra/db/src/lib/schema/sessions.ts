import { relations, sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  index,
  jsonb,
  pgTable,
  primaryKey,
  text,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { oauthClients, realms, users } from './core';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

/**
 * Why a browser session ended: the values `sessions.revoked_reason` accepts
 * (issue #468). The CHECK `sessions_revoked_reason_valid` is built from this
 * list, so the two cannot drift.
 *
 * - `sign_out` — the user signed out of this session.
 * - `sign_out_everywhere` — the user signed out of every session (ADR-019
 *   Decision 3).
 * - `admin` — an admin ended it.
 * - `reset` — a password or credential reset ended the sessions created before
 *   it.
 * - `key_retired` — the cookie key that signed it was retired.
 * - `browser_limit` — the browser held more account sessions than allowed, and
 *   this one was the oldest.
 * - `idle` — the realm's idle limit (`sso_idle_timeout`) passed.
 * - `expired` — the absolute end (`expires_at`) passed.
 */
export const SESSION_REVOKED_REASONS = [
  'sign_out',
  'sign_out_everywhere',
  'admin',
  'reset',
  'key_retired',
  'browser_limit',
  'idle',
  'expired',
] as const;

export type SessionRevokedReason = (typeof SESSION_REVOKED_REASONS)[number];

/**
 * Browser sessions (ADR-019 Decision 3, issue #468): Postgres is their source
 * of truth, and Redis a cache in front of it. ADR-014 calls this the browser
 * login session.
 *
 * A row is one account signed in on one browser, in one realm. Its `id` is the
 * session's `sid`, a `uuidv7()`: the value an ID token's `sid` claim and
 * back-channel logout name.
 *
 * Every lookup takes the realm as well as the id (ADR-019 Decision 1). The
 * composite foreign key `sessions_user_realm_fk` targets `users (id,
 * realm_id)`, so a row can never pair a user with another realm's id.
 *
 * Not stored here: the cookie, the CSRF values and the consent scopes. They are
 * volatile per-flow values and stay in the cache.
 *
 * Revocation is a soft end: `revoked_at` and `revoked_reason` are set together
 * (`sessions_revoked_pair`) and the row stays until a purge deletes it.
 * The idle limit is the realm's (`sso_idle_timeout`), judged from
 * `last_seen_at` by the session service.
 */
export const sessions = pgTable(
  'sessions',
  {
    /** The session's `sid`. */
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The signed-in user. Must belong to `realm_id` (`sessions_user_realm_fk`). */
    userId: uuid('user_id').notNull(),
    /**
     * When the user authenticated, in epoch milliseconds: what `max_age` and
     * the ID token's `auth_time` claim read (OpenID Connect Core 1.0 §2). Set
     * by the caller, because it is the time of the authentication, not of the
     * insert.
     */
    authTime: bigint('auth_time', { mode: 'number' }).notNull(),
    /**
     * The authentication methods used (the `amr` claim, RFC 8176), such as
     * `["pwd"]` or `["hwk", "user"]`. A JSON array.
     */
    amr: jsonb('amr').notNull().default(JSONB_EMPTY_ARRAY).$type<string[]>(),
    /**
     * The eIDAS level of assurance the authentication established:
     * `'substantial'` or `'high'`. NULL when nothing above `low` was
     * established, as on `authorization_codes.assurance_level`, so "no
     * assurance" has one representation.
     */
    assuranceLevel: text('assurance_level').$type<'substantial' | 'high'>(),
    /** The client address when the session was created. Not updated later. */
    ipAddress: varchar('ip_address', { length: 45 }),
    /** The `User-Agent` when the session was created. Not updated later. */
    userAgent: text('user_agent'),
    /** The absolute end, in epoch milliseconds. The session never outlives it. */
    expiresAt: bigint('expires_at', { mode: 'number' }).notNull(),
    revokedAt: bigint('revoked_at', { mode: 'number' }),
    revokedReason: text('revoked_reason').$type<SessionRevokedReason>(),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    /**
     * When the session was last used, in epoch milliseconds. Writes are
     * throttled, so it may lag the last use by up to the throttle interval.
     */
    lastSeenAt: bigint('last_seen_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    foreignKey({
      columns: [t.userId, t.realmId],
      foreignColumns: [users.id, users.realmId],
      name: 'sessions_user_realm_fk',
    }).onDelete('cascade'),
    // Serves the user foreign key's cascade, which must find revoked rows too.
    index('idx_sessions_user_id').on(t.userId),
    // A user's live sessions in a realm: listing, sign out everywhere.
    index('idx_sessions_realm_user_active')
      .on(t.realmId, t.userId)
      .where(sql`${t.revokedAt} IS NULL`),
    // Purging ended rows and sweeping expired ones.
    index('idx_sessions_expires_at').on(t.expiresAt),
    check('sessions_amr_is_array', sql`jsonb_typeof(${t.amr}) = 'array'`),
    check(
      'sessions_assurance_level_valid',
      sql`${t.assuranceLevel} IS NULL OR ${t.assuranceLevel} IN ('substantial', 'high')`
    ),
    check(
      'sessions_revoked_reason_valid',
      sql`${t.revokedReason} IN (${sql.raw(SESSION_REVOKED_REASONS.map((r) => `'${r}'`).join(', '))})`
    ),
    // Both directions: a revoked session always says why, and only a revoked
    // session carries a reason.
    check('sessions_revoked_pair', sql`(${t.revokedAt} IS NULL) = (${t.revokedReason} IS NULL)`),
  ]
);

/**
 * The clients a browser session has served (issue #468): one row per session
 * and client, written the first time the session authorizes that client.
 * Back-channel logout reads it to learn which clients to notify when the
 * session ends.
 *
 * Both foreign keys cascade: deleting the session or the client deletes the
 * row.
 */
export const sessionClients = pgTable(
  'session_clients',
  {
    sessionId: uuid('session_id')
      .notNull()
      .references(() => sessions.id, { onDelete: 'cascade' }),
    oauthClientId: uuid('oauth_client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    firstSeenAt: bigint('first_seen_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    primaryKey({ columns: [t.sessionId, t.oauthClientId], name: 'session_clients_pk' }),
    index('idx_session_clients_oauth_client_id').on(t.oauthClientId),
  ]
);

export const sessionsRelations = relations(sessions, ({ one, many }) => ({
  realm: one(realms, { fields: [sessions.realmId], references: [realms.id] }),
  user: one(users, { fields: [sessions.userId], references: [users.id] }),
  clients: many(sessionClients),
}));

export const sessionClientsRelations = relations(sessionClients, ({ one }) => ({
  session: one(sessions, { fields: [sessionClients.sessionId], references: [sessions.id] }),
  oauthClient: one(oauthClients, {
    fields: [sessionClients.oauthClientId],
    references: [oauthClients.id],
  }),
}));
