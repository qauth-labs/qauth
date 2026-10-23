import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  customType,
  index,
  jsonb,
  pgTable,
  smallint,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

/**
 * Postgres `xid8`, the 64-bit transaction id that never wraps around, read and
 * written as a `bigint`. node-postgres hands an `xid8` back as text, and
 * drizzle-orm has no built-in column for it.
 */
export const xid8 = customType<{ data: bigint; driverData: string }>({
  dataType() {
    return 'xid8';
  },
  fromDriver(value) {
    return BigInt(value);
  },
  toDriver(value) {
    return value.toString();
  },
});

/**
 * The event store (ADR-019 Decision 8, ADR-018 §3, issue #457): one
 * append-only table that is both the transactional outbox and the event log.
 *
 * An event is written in the transaction of the change it records
 * (`emit(tx, event)`), so the change and its event commit together, or
 * neither does. Each row is one envelope of the event contract
 * (`@qauth-labs/shared-events`), split into columns.
 *
 * ## Reading in order
 *
 * `seq` alone cannot order a reader: two transactions can commit in the
 * opposite order of their `seq` values, and a reader that had passed the later
 * one would skip the earlier. `xid` is the writing transaction's id. A row
 * whose `xid` is below the reader's snapshot xmin
 * (`pg_snapshot_xmin(pg_current_snapshot())`) was written by a transaction
 * that has ended, so no row can still appear before it. Readers take only
 * those rows, in `(xid, seq)` order (`readAfter`).
 *
 * ## No foreign keys
 *
 * `realm_id`, the actor, the subject and the client reference no table: an
 * event outlives the realm, user or client it names.
 *
 * ## Expand only
 *
 * The migration that creates the table holds only `CREATE TABLE` and
 * `CREATE INDEX`. The per-role grants (insert only for a writer) belong to
 * the topology area; the hash-chain columns of admin events and the trigger
 * that refuses updates come with #459.
 */
export const events = pgTable(
  'events',
  {
    /** Insertion order within a transaction; the tie-breaker of `(xid, seq)`. */
    seq: bigint('seq', { mode: 'bigint' }).primaryKey().generatedAlwaysAsIdentity(),
    /** The writing transaction's id, set by the database, never by the writer. */
    xid: xid8('xid')
      .notNull()
      .default(sql`pg_current_xact_id()`),
    /** The envelope `id`, a UUIDv7: one event keeps it on every route and retry. */
    id: uuid('id').notNull(),
    /** The envelope `realm`. */
    realmId: uuid('realm_id').notNull(),
    /** The envelope `category`, fixed by the type: `user` or `admin`. */
    category: varchar('category', { length: 16 }).notNull(),
    /** The envelope `type`: `urn:qauth:event:<name>:v<N>[-rc.<M>]`. */
    type: varchar('type', { length: 255 }).notNull(),
    /** The envelope `time`, in epoch milliseconds. */
    time: bigint('time', { mode: 'number' }).notNull(),
    /** `actor.type`; `null` when the event names no actor. */
    actorType: varchar('actor_type', { length: 32 }),
    /** `actor.id`; `null` for a `system` actor, or when there is no actor. */
    actorId: varchar('actor_id', { length: 255 }),
    /** `actor.delegationChain`: `client_id` values, the acting agent first. */
    actorDelegationChain: jsonb('actor_delegation_chain').$type<string[] | null>(),
    /** `subject.type`; `null` when the event has no subject. */
    subjectType: varchar('subject_type', { length: 32 }),
    /** `subject.id`: a plain id, never a foreign key. */
    subjectId: varchar('subject_id', { length: 255 }),
    /** `client.id`, the `client_id` of the client the request came through. */
    clientId: varchar('client_id', { length: 255 }),
    /** `request.traceId`, the id under which QAuth logged the request. */
    requestId: varchar('request_id', { length: 128 }),
    /** `request.ip`, personal data, present only where the contract allows it. */
    requestIp: varchar('request_ip', { length: 45 }),
    /** `request.userAgent`, cut to 1024 characters by the contract. */
    requestUserAgent: varchar('request_user_agent', { length: 1024 }),
    /** The envelope `data`, the type's own payload, as the registry validated it. */
    data: jsonb('data').$type<Record<string, unknown>>().notNull(),
    /**
     * The layout of this row: how its columns are read back into an envelope.
     * 1 for every row this release writes; a reader refuses a later one.
     */
    schemaVersion: smallint('schema_version').notNull(),
  },
  (t) => [
    unique('events_id_unique').on(t.id),
    check('events_id_uuidv7', sql`uuid_extract_version(${t.id}) = 7`),
    check('events_category_known', sql`${t.category} in ('user', 'admin')`),
    check('events_type_not_empty', sql`${t.type} <> ''`),
    check('events_data_is_object', sql`jsonb_typeof(${t.data}) = 'object'`),
    check(
      'events_actor_delegation_chain_is_array',
      sql`${t.actorDelegationChain} is null or jsonb_typeof(${t.actorDelegationChain}) = 'array'`
    ),
    check(
      'events_actor_has_type',
      sql`${t.actorType} is not null or (${t.actorId} is null and ${t.actorDelegationChain} is null)`
    ),
    check('events_subject_complete', sql`(${t.subjectType} is null) = (${t.subjectId} is null)`),
    check('events_schema_version_positive', sql`${t.schemaVersion} >= 1`),
    // Readers: a realm's rows in (xid, seq) order, from a position.
    index('idx_events_realm_position').on(t.realmId, t.xid, t.seq),
    index('idx_events_realm_type').on(t.realmId, t.type),
    index('idx_events_subject_id').on(t.subjectId),
    // Retention removes the oldest rows first (#536).
    index('idx_events_time').on(t.time),
  ]
);
