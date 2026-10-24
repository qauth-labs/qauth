import type { EventCategory } from '@qauth-labs/shared-events';
import { and, asc, eq, isNotNull, sql } from 'drizzle-orm';

import type {
  ClaimedEventDelivery,
  Database,
  DueEventDestination,
  EventDeliveriesRepository,
  EventDeliveryAttemptRecord,
  EventDeliveryClaimRef,
  EventDeliveryDestination,
  EventFanOutResult,
} from '../../types';
import { encodeEventPosition, type EventPosition } from '../events/position';
import { eventDeliveries, eventDeliveryPositions } from '../schema/event-deliveries';
import { events } from '../schema/events';
import {
  ENVELOPE_COLUMNS,
  envelopeOf,
  type EnvelopeRow,
  EVENT_READ_LIMIT_MAX,
} from './events.repository';

/**
 * The prefix of a realm's fan-out lock key. The lock is
 * `pg_try_advisory_xact_lock(hashtextextended(prefix || realm_id, 0))`, a key
 * no other lock of QAuth uses.
 */
export const EVENT_FAN_OUT_LOCK_PREFIX = 'qauth:events:fan-out:';

/** The events one fan-out page reads, unless the caller says otherwise. */
export const DEFAULT_FAN_OUT_PAGE_SIZE = 500;

/** The pages one fan-out reads of a realm, unless the caller says otherwise. */
export const DEFAULT_FAN_OUT_PAGES_PER_REALM = 10;

/**
 * The error class of an attempt that reported no outcome: its worker died or
 * was stopped while it ran, and the lease ran out or was given back.
 */
export const ATTEMPT_INTERRUPTED = 'attempt_interrupted';

/** An error class: a short machine-readable word, never a message. */
const ERROR_CLASS_PATTERN = /^[a-z][a-z0-9_]{0,63}$/;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const KIND_MAX_LENGTH = 32;
const DESTINATION_ID_MAX_LENGTH = 255;

/** An event as the fan-out reads it: what the filters match on, and its place. */
interface FanOutEventRow extends Record<string, unknown> {
  horizon: string;
  id: string | null;
  xid: string;
  seq: string;
  time: string;
  type: string;
  category: EventCategory;
}

/** A claimed row, with its event's columns. */
interface ClaimRow extends EnvelopeRow {
  delivery_id: string;
  destination_kind: string;
  destination_id: string;
  attempt: number;
  locked_until: string | null;
  status: string;
}

/** What one page of a realm's fan-out did. */
type PageOutcome =
  | { readonly kind: 'busy' }
  | { readonly kind: 'started' }
  | {
      readonly kind: 'read';
      readonly events: number;
      readonly deliveries: number;
      readonly full: boolean;
    };

function checkRealmId(realmId: string, caller: string): string {
  if (typeof realmId !== 'string' || !UUID_PATTERN.test(realmId)) {
    throw new TypeError(`eventDeliveries.${caller}: a realm id must be a UUID`);
  }
  return realmId.toLowerCase();
}

function checkKind(kind: string, caller: string): void {
  if (typeof kind !== 'string' || kind === '' || kind.length > KIND_MAX_LENGTH) {
    throw new TypeError(
      `eventDeliveries.${caller}: a route kind must be 1 to ${KIND_MAX_LENGTH} characters`
    );
  }
}

function checkDestination(destination: EventDeliveryDestination): void {
  checkKind(destination.kind, 'fanOut');
  if (
    typeof destination.id !== 'string' ||
    destination.id === '' ||
    destination.id.length > DESTINATION_ID_MAX_LENGTH
  ) {
    throw new TypeError(
      `eventDeliveries.fanOut: a destination id must be 1 to ${DESTINATION_ID_MAX_LENGTH} characters`
    );
  }
  checkRealmId(destination.realmId, 'fanOut');
}

function checkCount(value: number, min: number, max: number, what: string): number {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new TypeError(`eventDeliveries: ${what} must be an integer from ${min} to ${max}`);
  }
  return value;
}

function checkTime(value: number, what: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`eventDeliveries: ${what} must be epoch milliseconds`);
  }
  return value;
}

function checkOutcome(outcome: EventDeliveryAttemptRecord): void {
  const code = outcome.statusCode;
  if (code !== undefined && (!Number.isInteger(code) || code < 100 || code > 599)) {
    throw new TypeError('eventDeliveries.record: a status code must be an integer from 100 to 599');
  }
  if (outcome.result !== 'delivered' && !ERROR_CLASS_PATTERN.test(outcome.errorClass)) {
    throw new TypeError(
      'eventDeliveries.record: an error class must be lower-case letters, digits and _, at most 64'
    );
  }
  if (outcome.result === 'retry') checkTime(outcome.nextAttemptAt, 'nextAttemptAt');
}

/** Whether a destination's filters take an event of this type and category. */
function matches(
  destination: EventDeliveryDestination,
  type: string,
  category: EventCategory
): boolean {
  return (
    (destination.types === undefined || destination.types.includes(type)) &&
    (destination.categories === undefined || destination.categories.includes(category))
  );
}

/**
 * Factory for the delivery queue of the delivery role (ADR-019 Decision 8,
 * issue #460). See {@link EventDeliveriesRepository} for the guarantees.
 *
 * @param db - The database the delivery role connects to, as its own user
 *   (`eventDeliveryGrantStatements`).
 * @returns Repository implementing {@link EventDeliveriesRepository}
 */
export function createEventDeliveriesRepository(db: Database): EventDeliveriesRepository {
  /**
   * One page of one realm, in one transaction: read the events after the
   * realm's position and below the horizon, write their delivery rows, and
   * move the position. The page's events, rows and new position commit
   * together, or none of them does.
   */
  async function fanOutPage(
    realmId: string,
    destinations: readonly EventDeliveryDestination[],
    pageSize: number,
    now: number
  ): Promise<PageOutcome> {
    return db.transaction(
      async (tx): Promise<PageOutcome> => {
        const { rows: lock } = await tx.execute<{ locked: boolean }>(sql`
          select pg_try_advisory_xact_lock(hashtextextended(${EVENT_FAN_OUT_LOCK_PREFIX}::text || (${realmId})::uuid::text, 0)) as "locked"
        `);
        if (lock[0]?.locked !== true) return { kind: 'busy' };

        const [position] = await tx
          .select({
            xid: sql<string>`${eventDeliveryPositions.xid}::text`,
            seq: sql<string>`${eventDeliveryPositions.seq}::text`,
          })
          .from(eventDeliveryPositions)
          .where(eq(eventDeliveryPositions.realmId, realmId));

        // A realm seen for the first time starts at the horizon: its
        // destinations receive what is committed from now on.
        if (!position) {
          await tx.execute(sql`
            insert into ${eventDeliveryPositions} (realm_id, xid, seq, updated_at)
            select ${realmId}::uuid, pg_snapshot_xmin(pg_current_snapshot()), 0, ${now}
            on conflict (realm_id) do nothing
          `);
          return { kind: 'started' };
        }

        // One statement, so the horizon and the rows come from one snapshot,
        // as in the event store's readAfter: every row below the horizon is
        // final, and none can still appear before the last one read.
        const { rows } = await tx.execute<FanOutEventRow>(sql`
          select "horizon"."xmin"::text as "horizon", "page".*
          from (select pg_snapshot_xmin(pg_current_snapshot()) as "xmin") as "horizon"
          left join lateral (
            select ${events.id} as "id", ${events.xid}::text as "xid", ${events.seq}::text as "seq",
              ${events.time}::text as "time", ${events.type} as "type", ${events.category} as "category"
            from ${events}
            where ${events.realmId} = ${realmId}
              and (${events.xid}, ${events.seq}) > (${position.xid}::xid8, ${position.seq}::bigint)
              and ${events.xid} < "horizon"."xmin"
            order by ${events.xid}, ${events.seq}
            limit ${pageSize}
          ) as "page" on true
        `);
        const read = rows.filter((row): row is FanOutEventRow & { id: string } => row.id !== null);

        const kinds: string[] = [];
        const ids: string[] = [];
        const eventIds: string[] = [];
        const xids: string[] = [];
        const seqs: string[] = [];
        const times: string[] = [];
        for (const event of read) {
          for (const destination of destinations) {
            if (!matches(destination, event.type, event.category)) continue;
            kinds.push(destination.kind);
            ids.push(destination.id);
            eventIds.push(event.id);
            xids.push(event.xid);
            seqs.push(event.seq);
            times.push(event.time);
          }
        }
        let deliveries = 0;
        if (kinds.length > 0) {
          const inserted = await tx.execute(sql`
            insert into ${eventDeliveries} (destination_kind, destination_id, event_id, realm_id,
              event_xid, event_seq, event_time, next_attempt_at, created_at, updated_at)
            select "row"."kind", "row"."id", "row"."event_id", ${realmId}::uuid,
              "row"."xid"::xid8, "row"."seq"::bigint, "row"."time"::bigint, ${now}, ${now}, ${now}
            from unnest(${sql.param(kinds)}::text[], ${sql.param(ids)}::text[],
              ${sql.param(eventIds)}::uuid[], ${sql.param(xids)}::text[],
              ${sql.param(seqs)}::text[], ${sql.param(times)}::text[])
              as "row"("kind", "id", "event_id", "xid", "seq", "time")
            on conflict on constraint event_deliveries_event_destination_unique do nothing
          `);
          deliveries = inserted.rowCount ?? 0;
        }

        // A full page moves the position to its last event. A short one has
        // read every row below the horizon, so the position moves to the
        // horizon itself, as readAfter's `next` does; never backwards.
        const full = read.length === pageSize;
        let next = { xid: BigInt(position.xid), seq: BigInt(position.seq) };
        if (full) {
          const last = read[read.length - 1];
          next = { xid: BigInt(last.xid), seq: BigInt(last.seq) };
        } else {
          const horizon = BigInt(rows[0].horizon);
          if (horizon > next.xid) next = { xid: horizon, seq: 0n };
        }
        await tx
          .update(eventDeliveryPositions)
          .set({ xid: next.xid, seq: next.seq, updatedAt: now })
          .where(eq(eventDeliveryPositions.realmId, realmId));
        return { kind: 'read', events: read.length, deliveries, full };
      },
      { isolationLevel: 'read committed' }
    );
  }

  return {
    async fanOut(request): Promise<EventFanOutResult> {
      const now = checkTime(request.now, 'now');
      const pageSize = checkCount(
        request.pageSize ?? DEFAULT_FAN_OUT_PAGE_SIZE,
        1,
        EVENT_READ_LIMIT_MAX,
        'pageSize'
      );
      const maxPages = checkCount(
        request.maxPagesPerRealm ?? DEFAULT_FAN_OUT_PAGES_PER_REALM,
        1,
        1000,
        'maxPagesPerRealm'
      );
      const byRealm = new Map<string, EventDeliveryDestination[]>();
      for (const destination of request.destinations) {
        checkDestination(destination);
        const realm = destination.realmId.toLowerCase();
        const list = byRealm.get(realm) ?? [];
        list.push(destination);
        byRealm.set(realm, list);
      }
      const realms = [...byRealm.keys()];

      // A realm without a destination keeps no position: a destination
      // added later starts from its own time, not from where an earlier one
      // stopped.
      await db.execute(sql`
        delete from ${eventDeliveryPositions}
        where ${eventDeliveryPositions.realmId} <> all(${sql.param(realms)}::uuid[])
      `);

      const result = { realms: 0, skippedRealms: 0, events: 0, deliveries: 0, more: false };
      if (realms.length === 0) return result;

      // Only the realms with work: no position yet, or a final event after it.
      const { rows: waiting } = await db.execute<{ realm_id: string }>(sql`
        select "realm"."id"::text as "realm_id"
        from unnest(${sql.param(realms)}::uuid[]) as "realm"("id")
        left join ${eventDeliveryPositions} on ${eventDeliveryPositions.realmId} = "realm"."id"
        where ${eventDeliveryPositions.realmId} is null or exists (
          select 1 from ${events}
          where ${events.realmId} = "realm"."id"
            and (${events.xid}, ${events.seq}) > (${eventDeliveryPositions.xid}, ${eventDeliveryPositions.seq})
            and ${events.xid} < pg_snapshot_xmin(pg_current_snapshot())
        )
      `);

      for (const { realm_id: realmId } of waiting) {
        const destinations = byRealm.get(realmId) ?? [];
        let pages = 0;
        for (;;) {
          const page = await fanOutPage(realmId, destinations, pageSize, now);
          if (page.kind === 'busy') {
            result.skippedRealms += 1;
            break;
          }
          if (pages === 0) result.realms += 1;
          pages += 1;
          if (page.kind === 'started') break;
          result.events += page.events;
          result.deliveries += page.deliveries;
          if (!page.full) break;
          if (pages >= maxPages) {
            result.more = true;
            break;
          }
        }
      }
      return result;
    },

    async dueDestinations(kinds, now): Promise<DueEventDestination[]> {
      checkTime(now, 'now');
      const due: DueEventDestination[] = [];
      for (const kind of new Set(kinds)) {
        checkKind(kind, 'dueDestinations');
        // A loose index scan of idx_event_deliveries_due: one descent per
        // destination with a pending row, to its earliest due row.
        const { rows } = await db.execute<{ id: string }>(sql`
          with recursive "heads" as (
            (select ${eventDeliveries.destinationId} as "id", ${eventDeliveries.nextAttemptAt} as "due"
             from ${eventDeliveries}
             where ${eventDeliveries.status} = 'pending' and ${eventDeliveries.destinationKind} = ${kind}
             order by ${eventDeliveries.destinationId}, ${eventDeliveries.nextAttemptAt}
             limit 1)
            union all
            select "next"."id", "next"."due"
            from "heads" cross join lateral (
              select ${eventDeliveries.destinationId} as "id", ${eventDeliveries.nextAttemptAt} as "due"
              from ${eventDeliveries}
              where ${eventDeliveries.status} = 'pending' and ${eventDeliveries.destinationKind} = ${kind}
                and ${eventDeliveries.destinationId} > "heads"."id"
              order by ${eventDeliveries.destinationId}, ${eventDeliveries.nextAttemptAt}
              limit 1
            ) as "next"
          )
          select "id" from "heads" where "due" <= ${now}
        `);
        for (const row of rows) due.push({ kind, id: row.id });
      }
      return due;
    },

    async claim(request): Promise<ClaimedEventDelivery[]> {
      const now = checkTime(request.now, 'now');
      const leaseMs = checkCount(request.leaseMs, 1, 24 * 60 * 60_000, 'leaseMs');
      const maxAttempts = checkCount(request.maxAttempts, 1, 1000, 'maxAttempts');
      const picks = request.picks.filter((pick) => pick.limit > 0);
      if (picks.length === 0) return [];
      for (const pick of picks) {
        checkKind(pick.kind, 'claim');
        checkCount(pick.limit, 1, 1000, 'a pick limit');
      }
      const leaseEnd = now + leaseMs;

      // The claim counts the attempt and leases the row: `next_attempt_at`
      // becomes the lease's end, so the row comes due again only when the
      // lease runs out. A row whose attempts are used up was interrupted on
      // its last one; it ends `failed` here instead of being attempted again.
      const { rows } = await db.execute<ClaimRow>(sql`
        with "pick" as (
          select * from unnest(${sql.param(picks.map((pick) => pick.kind))}::text[],
            ${sql.param(picks.map((pick) => pick.id))}::text[],
            ${sql.param(picks.map((pick) => pick.limit))}::int[]) as "pick"("kind", "id", "n")
        ), "picked" as (
          select "row"."id" from "pick" cross join lateral (
            select ${eventDeliveries.id} as "id" from ${eventDeliveries}
            where ${eventDeliveries.destinationKind} = "pick"."kind"
              and ${eventDeliveries.destinationId} = "pick"."id"
              and ${eventDeliveries.status} = 'pending'
              and ${eventDeliveries.nextAttemptAt} <= ${now}
            order by ${eventDeliveries.nextAttemptAt}
            limit "pick"."n"
            for update skip locked
          ) as "row"
        )
        update ${eventDeliveries} set
          attempt_count = case when attempt_count < ${maxAttempts} then attempt_count + 1 else attempt_count end,
          status = case when attempt_count < ${maxAttempts} then 'pending' else 'failed' end,
          locked_until = case when attempt_count < ${maxAttempts} then ${leaseEnd}::bigint end,
          next_attempt_at = case when attempt_count < ${maxAttempts} then ${leaseEnd} else next_attempt_at end,
          last_error_class = case when attempt_count < ${maxAttempts} then last_error_class else ${ATTEMPT_INTERRUPTED} end,
          finished_at = case when attempt_count < ${maxAttempts} then null else ${now}::bigint end,
          updated_at = ${now}
        from "picked", ${events}
        where ${eventDeliveries.id} = "picked"."id" and ${events.id} = ${eventDeliveries.eventId}
        returning ${eventDeliveries.id} as "delivery_id",
          ${eventDeliveries.destinationKind} as "destination_kind",
          ${eventDeliveries.destinationId} as "destination_id",
          ${eventDeliveries.attemptCount} as "attempt",
          ${eventDeliveries.lockedUntil}::text as "locked_until",
          ${eventDeliveries.status} as "status",
          ${ENVELOPE_COLUMNS}
      `);

      return rows
        .filter((row) => row.status === 'pending' && row.locked_until !== null)
        .map((row) => {
          let event: ClaimedEventDelivery['event'];
          try {
            event = envelopeOf(row);
          } catch {
            event = null;
          }
          return {
            id: row.delivery_id,
            attempt: row.attempt,
            destinationKind: row.destination_kind,
            destinationId: row.destination_id,
            realmId: row.realm_id,
            eventId: row.id,
            lockedUntil: Number(row.locked_until),
            event,
          };
        });
    },

    async record(claim, outcome, now): Promise<boolean> {
      checkTime(now, 'now');
      checkOutcome(outcome);
      const done = outcome.result !== 'retry';
      const result = await db
        .update(eventDeliveries)
        .set({
          status: outcome.result === 'retry' ? 'pending' : outcome.result,
          lockedUntil: null,
          ...(outcome.result === 'retry' ? { nextAttemptAt: outcome.nextAttemptAt } : {}),
          lastStatusCode: outcome.statusCode ?? null,
          lastErrorClass: outcome.result === 'delivered' ? null : outcome.errorClass,
          finishedAt: done ? now : null,
          updatedAt: now,
        })
        .where(claimed(claim));
      return (result.rowCount ?? 0) > 0;
    },

    async release(claims, now): Promise<number> {
      checkTime(now, 'now');
      if (claims.length === 0) return 0;
      const result = await db.execute(sql`
        update ${eventDeliveries} set locked_until = null, next_attempt_at = ${now},
          last_error_class = ${ATTEMPT_INTERRUPTED}, updated_at = ${now}
        from unnest(${sql.param(claims.map((claim) => claim.id))}::uuid[],
          ${sql.param(claims.map((claim) => claim.attempt))}::int[]) as "claim"("id", "attempt")
        where ${eventDeliveries.id} = "claim"."id"
          and ${eventDeliveries.attemptCount} = "claim"."attempt"
          and ${eventDeliveries.status} = 'pending'
          and ${eventDeliveries.lockedUntil} is not null
      `);
      return result.rowCount ?? 0;
    },

    async minOffered(realmId): Promise<EventPosition> {
      const realm = checkRealmId(realmId, 'minOffered');
      // One statement: the position, the oldest unfinished row and the
      // horizon from one snapshot, so a fan-out that commits between them
      // cannot be half seen.
      const { rows } = await db.execute<{
        horizon: string;
        position_xid: string | null;
        position_seq: string | null;
        waiting_xid: string | null;
        waiting_seq: string | null;
      }>(sql`
        select pg_snapshot_xmin(pg_current_snapshot())::text as "horizon",
          ${eventDeliveryPositions.xid}::text as "position_xid",
          ${eventDeliveryPositions.seq}::text as "position_seq",
          "waiting"."xid"::text as "waiting_xid", "waiting"."seq"::text as "waiting_seq"
        from (select 1) as "one"
        left join ${eventDeliveryPositions} on ${eventDeliveryPositions.realmId} = ${realm}
        left join lateral (
          select ${eventDeliveries.eventXid} as "xid", ${eventDeliveries.eventSeq} as "seq"
          from ${eventDeliveries}
          where ${eventDeliveries.realmId} = ${realm} and ${eventDeliveries.status} = 'pending'
          order by ${eventDeliveries.eventXid}, ${eventDeliveries.eventSeq}
          limit 1
        ) as "waiting" on true
      `);
      const row = rows[0];
      // Without a position the realm has no destination: nothing below the
      // horizon will be fanned out any more.
      let xid = BigInt(row.position_xid ?? row.horizon);
      let seq = BigInt(row.position_seq ?? '0');
      if (row.waiting_xid !== null && row.waiting_seq !== null) {
        // Everything before the oldest unfinished event is finished.
        const waitingXid = BigInt(row.waiting_xid);
        const before = BigInt(row.waiting_seq) - 1n;
        if (waitingXid < xid || (waitingXid === xid && before < seq)) {
          xid = waitingXid;
          seq = before;
        }
      }
      return encodeEventPosition({ realmId: realm, xid, seq });
    },

    async pendingByKind(): Promise<Record<string, number>> {
      const rows = await db
        .select({ kind: eventDeliveries.destinationKind, count: sql<number>`count(*)::int` })
        .from(eventDeliveries)
        .where(eq(eventDeliveries.status, 'pending'))
        .groupBy(eventDeliveries.destinationKind);
      return Object.fromEntries(rows.map((row) => [row.kind, row.count]));
    },

    async deliveryLagSeconds(now): Promise<number> {
      checkTime(now, 'now');
      // The oldest event an unfinished row waits on, and the oldest event the
      // fan-out has not read yet (the first after each realm's position).
      const { rows } = await db.execute<{ oldest: string | null }>(sql`
        select least(
          (select min(${eventDeliveries.eventTime}) from ${eventDeliveries}
           where ${eventDeliveries.status} = 'pending'),
          (select min("unread"."time") from ${eventDeliveryPositions} cross join lateral (
             select ${events.time} as "time" from ${events}
             where ${events.realmId} = ${eventDeliveryPositions.realmId}
               and (${events.xid}, ${events.seq}) > (${eventDeliveryPositions.xid}, ${eventDeliveryPositions.seq})
             order by ${events.xid}, ${events.seq}
             limit 1
           ) as "unread")
        )::text as "oldest"
      `);
      const oldest = rows[0]?.oldest;
      if (oldest === null || oldest === undefined) return 0;
      return Math.max(0, now - Number(oldest)) / 1000;
    },

    async listForEvent(eventId) {
      if (typeof eventId !== 'string' || !UUID_PATTERN.test(eventId)) {
        throw new TypeError('eventDeliveries.listForEvent: an event id must be a UUID');
      }
      return db
        .select()
        .from(eventDeliveries)
        .where(eq(eventDeliveries.eventId, eventId))
        .orderBy(asc(eventDeliveries.createdAt), asc(eventDeliveries.id));
    },
  };
}

/**
 * The row a claim still holds: the attempt it made is the row's latest, the
 * row is not finished, and its lease was not given back.
 */
function claimed(claim: EventDeliveryClaimRef) {
  return and(
    eq(eventDeliveries.id, claim.id),
    eq(eventDeliveries.attemptCount, claim.attempt),
    eq(eventDeliveries.status, 'pending'),
    isNotNull(eventDeliveries.lockedUntil)
  );
}
