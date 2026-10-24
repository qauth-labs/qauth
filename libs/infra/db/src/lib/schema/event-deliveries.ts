import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  index,
  integer,
  pgTable,
  primaryKey,
  smallint,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { events, xid8 } from './events';
import { EPOCH_MS_NOW } from './sql-helpers';

/**
 * Where a delivery stands: the values `event_deliveries.status` accepts
 * (issue #460). The CHECK `event_deliveries_status_known` is built from this
 * list, so the two cannot drift.
 *
 * - `pending` — not finished: waiting for its next attempt, or claimed by a
 *   worker whose lease has not run out.
 * - `delivered` — the destination accepted the event.
 * - `failed` — the last attempt failed, or the route refused the event for
 *   good. The row stays, so the history can show it.
 */
export const EVENT_DELIVERY_STATUSES = ['pending', 'delivered', 'failed'] as const;

export type EventDeliveryStatus = (typeof EVENT_DELIVERY_STATUSES)[number];

/**
 * The deliveries of the delivery role (ADR-019 Decision 8, issue #460): one
 * row per destination and event, the unit of at-least-once delivery.
 *
 * The fan-out writes a row for every destination whose filter matches an
 * event, and a worker claims rows, hands each event to its route and records
 * the outcome. Rows are per destination, so a destination that is down only
 * delays its own rows.
 *
 * ## Claims and leases
 *
 * A worker claims a row with `FOR UPDATE SKIP LOCKED` and leases it until
 * `locked_until`. A claim also counts the attempt and moves `next_attempt_at`
 * to the lease's end, so a worker that dies mid-attempt leaves a row that
 * becomes due again when the lease runs out, and the event is delivered again.
 * Every claim raises `attempt_count`, which the outcome's write names: a
 * worker whose lease ran out and was claimed again cannot overwrite the newer
 * attempt.
 *
 * The times are epoch milliseconds from the worker's clock, not the
 * database's, so the lease and the retry schedule run on one clock.
 *
 * ## Position
 *
 * `realm_id`, `event_xid` and `event_seq` copy the event's place in its
 * realm's stream, so the lowest position every destination has finished
 * (`minOffered`, for the retention job of #536) is read from this table alone.
 * `event_time` copies the event's time, for the lag gauge.
 *
 * ## Lifetime
 *
 * A row lives as long as its event: deleting the event deletes its rows. The
 * retention job deletes only events every destination has finished.
 */
export const eventDeliveries = pgTable(
  'event_deliveries',
  {
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    /** The route that delivers: `webhook`, `ssf`, … (the route's `kind`). */
    destinationKind: varchar('destination_kind', { length: 32 }).notNull(),
    /** The destination within its route, such as a webhook subscription's id. */
    destinationId: varchar('destination_id', { length: 255 }).notNull(),
    /** The envelope `id`: the receiver drops a duplicate by it. */
    eventId: uuid('event_id')
      .notNull()
      .references(() => events.id, { onDelete: 'cascade' }),
    /** The event's realm. */
    realmId: uuid('realm_id').notNull(),
    /** The event's `xid`: with `event_seq`, its place in the realm's stream. */
    eventXid: xid8('event_xid').notNull(),
    /** The event's `seq`. */
    eventSeq: bigint('event_seq', { mode: 'bigint' }).notNull(),
    /** The event's `time`, in epoch milliseconds. */
    eventTime: bigint('event_time', { mode: 'number' }).notNull(),
    status: varchar('status', { length: 16 })
      .$type<EventDeliveryStatus>()
      .notNull()
      .default('pending'),
    /** The attempts made, counted when a worker claims the row. */
    attemptCount: integer('attempt_count').notNull().default(0),
    /** When the row is next due, in epoch milliseconds: a retry's time, or a lease's end. */
    nextAttemptAt: bigint('next_attempt_at', { mode: 'number' }).notNull(),
    /** The end of the current claim's lease; `null` while no worker holds the row. */
    lockedUntil: bigint('locked_until', { mode: 'number' }),
    /** The HTTP status the destination last answered, when it answered. */
    lastStatusCode: smallint('last_status_code'),
    /** Why the last attempt failed, as a short class such as `timeout`; never a message. */
    lastErrorClass: varchar('last_error_class', { length: 64 }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    /** When the row became `delivered` or `failed`; `null` while it is `pending`. */
    finishedAt: bigint('finished_at', { mode: 'number' }),
  },
  (t) => [
    // One row per destination and event: a fan-out that runs twice adds none.
    unique('event_deliveries_event_destination_unique').on(
      t.eventId,
      t.destinationKind,
      t.destinationId
    ),
    check(
      'event_deliveries_status_known',
      sql`${t.status} in (${sql.raw(EVENT_DELIVERY_STATUSES.map((s) => `'${s}'`).join(', '))})`
    ),
    check('event_deliveries_destination_kind_not_empty', sql`${t.destinationKind} <> ''`),
    check('event_deliveries_destination_id_not_empty', sql`${t.destinationId} <> ''`),
    check('event_deliveries_attempt_count_valid', sql`${t.attemptCount} >= 0`),
    check(
      'event_deliveries_last_status_code_valid',
      sql`${t.lastStatusCode} is null or ${t.lastStatusCode} between 100 and 599`
    ),
    check(
      'event_deliveries_finished_when_done',
      sql`(${t.status} = 'pending') = (${t.finishedAt} is null)`
    ),
    check(
      'event_deliveries_lease_while_pending',
      sql`${t.lockedUntil} is null or ${t.status} = 'pending'`
    ),
    // Claims: a destination's pending rows, earliest due first. The claim
    // also walks it to find the destinations with work.
    index('idx_event_deliveries_due')
      .on(t.destinationKind, t.destinationId, t.nextAttemptAt)
      .where(sql`${t.status} = 'pending'`),
    // minOffered: a realm's oldest unfinished row by stream position.
    index('idx_event_deliveries_pending_position')
      .on(t.realmId, t.eventXid, t.eventSeq)
      .where(sql`${t.status} = 'pending'`),
    // The lag gauge: the oldest event a row still waits to deliver.
    index('idx_event_deliveries_pending_time')
      .on(t.eventTime)
      .where(sql`${t.status} = 'pending'`),
  ]
);

/**
 * How far the fan-out has read each realm's stream for each route kind
 * (issue #460): the position after which it next reads.
 *
 * One row per realm and kind, so a node that serves fewer kinds than another,
 * such as a node of an older release during a rollout, moves and forgets only
 * the positions of its own kinds. A row exists only while the realm has a
 * destination of that kind; the fan-out removes it when the last one goes, so
 * a destination added later starts from that time, not from the old position.
 */
export const eventDeliveryPositions = pgTable(
  'event_delivery_positions',
  {
    realmId: uuid('realm_id').notNull(),
    /** The route kind whose destinations this position feeds. */
    destinationKind: varchar('destination_kind', { length: 32 }).notNull(),
    /** The `xid` of the position: the last event read, or a horizon. */
    xid: xid8('xid').notNull(),
    /** The `seq` of the position; 0 before the first event of `xid`. */
    seq: bigint('seq', { mode: 'bigint' }).notNull(),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    primaryKey({ columns: [t.realmId, t.destinationKind], name: 'event_delivery_positions_pk' }),
    check('event_delivery_positions_seq_valid', sql`${t.seq} >= 0`),
    check('event_delivery_positions_kind_not_empty', sql`${t.destinationKind} <> ''`),
  ]
);
