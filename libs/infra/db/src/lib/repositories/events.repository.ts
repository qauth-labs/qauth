import {
  type EventEnvelope,
  EventValidationError,
  getEventType,
  parseEvent,
} from '@qauth-labs/shared-events';
import { and, eq, gte, inArray, type SQL, sql } from 'drizzle-orm';

import type {
  Database,
  DbClient,
  EmitEvent,
  EventPage,
  EventReadFilters,
  EventsRepository,
  EventsRepositoryOptions,
  StoredEvent,
} from '../../types';
import {
  compareEventPositions,
  decodeEventPosition,
  encodeEventPosition,
  type EventPosition,
  EventPositionError,
  type EventPositionParts,
} from '../events/position';
import { uuidv7 } from '../events/uuidv7';
import { events } from '../schema/events';

/**
 * The layout of the rows this release writes (`events.schema_version`): how
 * the columns are read back into an envelope. A reader refuses a row with a
 * later layout rather than guess at it.
 */
export const EVENT_ROW_SCHEMA_VERSION = 1;

/** The most events one {@link EventsRepository.readAfter} returns. */
export const EVENT_READ_LIMIT_MAX = 1000;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type NewEventRow = typeof events.$inferInsert;

/** An emitted event of any type, before it is checked: what `emit` sees at run time. */
type UncheckedEvent = Omit<EmitEvent, 'type' | 'data'> & { type: string; data: unknown };

/** The JSON-pointer-like paths of every string under `value` that holds U+0000. */
function nulPaths(value: unknown, path: string): string[] {
  if (typeof value === 'string') return value.includes('\u0000') ? [path] : [];
  if (Array.isArray(value)) return value.flatMap((item, i) => nulPaths(item, `${path}/${i}`));
  if (value !== null && typeof value === 'object') {
    return Object.entries(value).flatMap(([key, item]) => [
      ...(key.includes('\u0000') ? [`${path}/${key}`] : []),
      ...nulPaths(item, `${path}/${key}`),
    ]);
  }
  return [];
}

/**
 * The envelope an emitted event becomes, checked against the registry, and
 * the row that stores it.
 *
 * @throws {EventValidationError} on an unknown type or an event that fails
 *   `parseEvent`, or one Postgres could not store
 */
function buildEventRow(event: UncheckedEvent, at: number): NewEventRow {
  const definition = getEventType(event.type);
  if (!definition) {
    throw new EventValidationError('unknown event type', [`${event.type} is not in the registry`]);
  }
  // Postgres prints a UUID in lower case; the realm is stored and read back so.
  const realm = typeof event.realm === 'string' ? event.realm.toLowerCase() : event.realm;
  const envelope = parseEvent({
    id: uuidv7(at),
    type: event.type,
    time: new Date(at).toISOString(),
    realm,
    category: definition.category,
    ...(event.actor === undefined ? {} : { actor: event.actor }),
    ...(event.subject === undefined ? {} : { subject: event.subject }),
    ...(event.client === undefined ? {} : { client: event.client }),
    ...(event.request === undefined ? {} : { request: event.request }),
    data: event.data,
  });
  // Neither `text` nor `jsonb` can hold U+0000, and a failed insert would
  // abort the caller's transaction with a less useful error.
  const unstorable = nulPaths(envelope, '');
  if (unstorable.length > 0) {
    throw new EventValidationError(
      `not a storable ${envelope.type} event`,
      unstorable.map((path) => `${path}: holds a NUL character, which Postgres cannot store`)
    );
  }
  return {
    id: envelope.id,
    realmId: envelope.realm,
    category: envelope.category,
    type: envelope.type,
    time: at,
    actorType: envelope.actor?.type ?? null,
    actorId: envelope.actor?.id ?? null,
    actorDelegationChain: envelope.actor?.delegationChain ?? null,
    subjectType: envelope.subject?.type ?? null,
    subjectId: envelope.subject?.id ?? null,
    clientId: envelope.client?.id ?? null,
    requestId: envelope.request?.traceId ?? null,
    requestIp: envelope.request?.ip ?? null,
    requestUserAgent: envelope.request?.userAgent ?? null,
    data: envelope.data,
    schemaVersion: EVENT_ROW_SCHEMA_VERSION,
  };
}

async function insertEvent(client: DbClient, row: NewEventRow): Promise<string> {
  // No RETURNING: a writer granted only INSERT may not read the row back.
  await client.insert(events).values(row);
  return row.id;
}

/** A row of the read, as node-postgres returns it: `bigint` and `xid8` as text. */
interface ReadRow extends Record<string, unknown> {
  horizon: string;
  seq: string | null;
  xid: string;
  id: string;
  realm_id: string;
  category: EventEnvelope['category'];
  type: string;
  time: string;
  actor_type: string | null;
  actor_id: string | null;
  actor_delegation_chain: string[] | null;
  subject_type: string | null;
  subject_id: string | null;
  client_id: string | null;
  request_id: string | null;
  request_ip: string | null;
  request_user_agent: string | null;
  data: Record<string, unknown>;
  schema_version: number;
}

/**
 * The envelope a stored row holds, with every member the row has and none it
 * lacks.
 *
 * @throws {Error} on a row written in a later layout than this release reads
 */
function toStoredEvent(row: ReadRow & { seq: string }): StoredEvent {
  if (row.schema_version !== EVENT_ROW_SCHEMA_VERSION) {
    throw new Error(
      `events: event ${row.id} is stored in layout ${row.schema_version}, which this release cannot read`
    );
  }
  const request = {
    ...(row.request_id === null ? {} : { traceId: row.request_id }),
    ...(row.request_ip === null ? {} : { ip: row.request_ip }),
    ...(row.request_user_agent === null ? {} : { userAgent: row.request_user_agent }),
  };
  const event = {
    id: row.id,
    type: row.type,
    time: new Date(Number(row.time)).toISOString(),
    realm: row.realm_id,
    category: row.category,
    ...(row.actor_type === null
      ? {}
      : {
          actor: {
            type: row.actor_type,
            ...(row.actor_id === null ? {} : { id: row.actor_id }),
            ...(row.actor_delegation_chain === null
              ? {}
              : { delegationChain: row.actor_delegation_chain }),
          },
        }),
    ...(row.subject_type === null || row.subject_id === null
      ? {}
      : { subject: { type: row.subject_type, id: row.subject_id } }),
    ...(row.client_id === null ? {} : { client: { id: row.client_id } }),
    ...(Object.keys(request).length === 0 ? {} : { request }),
    data: row.data,
  } as EventEnvelope;
  return {
    position: encodeEventPosition({
      realmId: row.realm_id,
      xid: BigInt(row.xid),
      seq: BigInt(row.seq),
    }),
    event,
  };
}

function checkRealmId(realmId: string): string {
  if (typeof realmId !== 'string' || !UUID_PATTERN.test(realmId)) {
    throw new TypeError('events: a read needs the id of the realm it reads, a UUID');
  }
  return realmId.toLowerCase();
}

function filterConditions(filters: EventReadFilters): SQL[] {
  const conditions: SQL[] = [];
  if (filters.types !== undefined) conditions.push(inArray(events.type, [...filters.types]));
  if (filters.category !== undefined) conditions.push(eq(events.category, filters.category));
  if (filters.subjectId !== undefined) conditions.push(eq(events.subjectId, filters.subjectId));
  if (filters.clientId !== undefined) conditions.push(eq(events.clientId, filters.clientId));
  if (filters.fromTime !== undefined) {
    if (!Number.isSafeInteger(filters.fromTime)) {
      throw new TypeError('events: fromTime must be epoch milliseconds');
    }
    conditions.push(gte(events.time, filters.fromTime));
  }
  return conditions;
}

/**
 * Factory for the event store repository (ADR-019 Decision 8, issue #457).
 * See {@link EventsRepository} for the write rule, the read rule and the lag.
 *
 * @param defaultDb - The root database: reads, and the writes of
 *   `emitInOwnTransaction`, run on it.
 * @param options - The clock.
 * @returns Repository implementing {@link EventsRepository}
 */
export function createEventsRepository(
  defaultDb: Database,
  options: EventsRepositoryOptions = {}
): EventsRepository {
  const now = options.now ?? Date.now;

  return {
    async emit(tx, event) {
      return insertEvent(tx, buildEventRow(event, now()));
    },

    async emitInOwnTransaction(event) {
      // One INSERT on the root database is a transaction of its own.
      return insertEvent(defaultDb, buildEventRow(event, now()));
    },

    async readAfter(realmId, position, limit, filters = {}): Promise<EventPage> {
      const realm = checkRealmId(realmId);
      const from = decodeEventPosition(position);
      if (from.realmId !== realm) {
        throw new EventPositionError('event position: the position belongs to another realm');
      }
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > EVENT_READ_LIMIT_MAX) {
        throw new TypeError(
          `events: the limit must be an integer from 1 to ${EVENT_READ_LIMIT_MAX}`
        );
      }

      // One statement, so the horizon and the rows come from one snapshot.
      // The horizon is that snapshot's xmin: every transaction below it has
      // ended, so the rows below it are final. The left join returns the
      // horizon even when no row qualifies.
      const where = and(
        eq(events.realmId, realm),
        sql`(${events.xid}, ${events.seq}) > (${from.xid.toString()}::xid8, ${from.seq.toString()}::bigint)`,
        sql`${events.xid} < "horizon"."xmin"`,
        ...filterConditions(filters)
      );
      const { rows } = await defaultDb.execute<ReadRow>(sql`
        select "horizon"."xmin"::text as "horizon", "page".*
        from (select pg_snapshot_xmin(pg_current_snapshot()) as "xmin") as "horizon"
        left join lateral (
          select ${events.seq}::text as "seq", ${events.xid}::text as "xid", ${events.id} as "id",
            ${events.realmId} as "realm_id", ${events.category} as "category",
            ${events.type} as "type", ${events.time}::text as "time",
            ${events.actorType} as "actor_type", ${events.actorId} as "actor_id",
            ${events.actorDelegationChain} as "actor_delegation_chain",
            ${events.subjectType} as "subject_type", ${events.subjectId} as "subject_id",
            ${events.clientId} as "client_id", ${events.requestId} as "request_id",
            ${events.requestIp} as "request_ip", ${events.requestUserAgent} as "request_user_agent",
            ${events.data} as "data", ${events.schemaVersion} as "schema_version"
          from ${events}
          where ${where}
          order by ${events.xid}, ${events.seq}
          limit ${limit}
        ) as "page" on true
      `);

      const page = rows
        .filter((row): row is ReadRow & { seq: string } => row.seq !== null)
        .map(toStoredEvent);
      let next: EventPosition;
      if (page.length === limit) {
        next = page[page.length - 1].position;
      } else {
        // Fewer rows than asked: every matching row below the horizon has been
        // returned, so reading on can start at the horizon itself. Rows of the
        // transaction at the horizon have seq >= 1 and still come after it.
        const horizon: EventPositionParts = {
          realmId: realm,
          xid: BigInt(rows[0].horizon),
          seq: 0n,
        };
        next = encodeEventPosition(compareEventPositions(horizon, from) > 0 ? horizon : from);
      }
      return { events: page, next };
    },

    async oldestUnreadEventAge() {
      // Postgres 18 answers this from idx_events_realm_position with a skip
      // scan: one descent per realm, to the rows at or above the horizon.
      const { rows } = await defaultDb.execute<{ oldest: string | null }>(sql`
        select min(${events.time})::text as "oldest"
        from ${events}
        where ${events.xid} >= pg_snapshot_xmin(pg_current_snapshot())
      `);
      const oldest = rows[0]?.oldest;
      if (oldest === null || oldest === undefined) return 0;
      return Math.max(0, now() - Number(oldest)) / 1000;
    },
  };
}
