import {
  type AdminApproval,
  adminChangeApplied,
  buildAdminDiff,
  type EventEnvelope,
  EventValidationError,
  getEventType,
  parseEvent,
} from '@qauth-labs/shared-events';
import { and, desc, eq, gte, inArray, isNotNull, type SQL, sql } from 'drizzle-orm';

import type {
  AdminEventInput,
  Database,
  DbClient,
  DbTransaction,
  EmitEvent,
  EventChainBreakReason,
  EventChainPoint,
  EventChainReport,
  EventPage,
  EventReadFilters,
  EventsRepository,
  EventsRepositoryOptions,
  StoredEvent,
} from '../../types';
import { EVENT_CHAIN_GENESIS_HASH, EVENT_CHAIN_LOCK_PREFIX, eventChainHash } from '../events/chain';
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

const DEFAULT_VERIFY_BATCH_SIZE = 500;

const SHA256_HEX = /^[0-9a-f]{64}$/i;

type NewEventRow = typeof events.$inferInsert;

/** A checked event: the row that stores it and the envelope it is. */
interface BuiltEvent {
  row: NewEventRow & { id: string; realmId: string };
  envelope: EventEnvelope;
}

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
function buildEvent(event: UncheckedEvent, at: number): BuiltEvent {
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
  const row = {
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
  return { row, envelope };
}

async function insertEvent(client: DbClient, row: NewEventRow): Promise<string> {
  // No RETURNING: a writer granted only INSERT may not read the row back.
  await client.insert(events).values(row);
  return row.id;
}

/**
 * The columns a reader turns back into an envelope, named as {@link EnvelopeRow}
 * names them: `bigint` and `xid8` as text.
 */
const ENVELOPE_COLUMNS = sql`${events.seq}::text as "seq", ${events.xid}::text as "xid",
  ${events.id} as "id", ${events.realmId} as "realm_id", ${events.category} as "category",
  ${events.type} as "type", ${events.time}::text as "time",
  ${events.actorType} as "actor_type", ${events.actorId} as "actor_id",
  ${events.actorDelegationChain} as "actor_delegation_chain",
  ${events.subjectType} as "subject_type", ${events.subjectId} as "subject_id",
  ${events.clientId} as "client_id", ${events.requestId} as "request_id",
  ${events.requestIp} as "request_ip", ${events.requestUserAgent} as "request_user_agent",
  ${events.data} as "data", ${events.schemaVersion} as "schema_version"`;

/** A stored row, as {@link ENVELOPE_COLUMNS} reads it. */
interface EnvelopeRow extends Record<string, unknown> {
  seq: string;
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

/** A row of the read: the horizon, and a row's columns, all `null` when none qualified. */
type ReadRow = Record<string, unknown> & { horizon: string; seq: string | null };

/** An admin row with its chain columns. */
interface ChainRow extends EnvelopeRow {
  prev_hash: Buffer;
  hash: Buffer;
}

/**
 * The envelope a stored row holds, with every member the row has and none it
 * lacks: the envelope the row's writer emitted.
 *
 * @throws {Error} on a row written in a later layout than this release reads
 */
function envelopeOf(row: EnvelopeRow): EventEnvelope {
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
  return event;
}

/** A stored row, as a reader of the stream gets it. */
function toStoredEvent(row: EnvelopeRow): StoredEvent {
  return {
    position: encodeEventPosition({
      realmId: row.realm_id,
      xid: BigInt(row.xid),
      seq: BigInt(row.seq),
    }),
    event: envelopeOf(row),
  };
}

/**
 * Write an admin event as the next link of its realm's chain, in the
 * caller's transaction. See {@link EventsRepository.emit}.
 *
 * @throws {Error} when the stored row does not hash as written; nothing is
 *   then committed, since the error rolls back the caller's transaction
 */
async function appendToChain(tx: DbTransaction, { row, envelope }: BuiltEvent): Promise<string> {
  await tx.execute(
    sql`select pg_advisory_xact_lock(hashtextextended(${EVENT_CHAIN_LOCK_PREFIX}::text || (${row.realmId})::uuid::text, 0))`
  );
  const [head] = await tx
    .select({ hash: events.hash })
    .from(events)
    .where(and(eq(events.realmId, row.realmId), isNotNull(events.hash)))
    .orderBy(desc(events.seq))
    .limit(1);
  const prevHash = head?.hash ?? EVENT_CHAIN_GENESIS_HASH;
  const hash = eventChainHash(prevHash, envelope);
  await tx.insert(events).values({ ...row, prevHash, hash });

  // The row as Postgres stores it must hash to its hash, or the chain would
  // break at this row for good.
  const { rows } = await tx.execute<ChainRow>(sql`
    select ${ENVELOPE_COLUMNS}, ${events.prevHash} as "prev_hash", ${events.hash} as "hash"
    from ${events} where ${events.id} = ${row.id}
  `);
  if (rows.length !== 1 || checkChainRow(rows[0], prevHash) !== undefined) {
    throw new Error(
      `events: admin event ${row.id} does not hash as it was written; nothing was emitted`
    );
  }
  return row.id;
}

/** Why an admin row does not continue the chain after `expectedPrev`, if it does not. */
function checkChainRow(row: ChainRow, expectedPrev: Buffer): EventChainBreakReason | undefined {
  if (!Buffer.isBuffer(row.prev_hash) || !row.prev_hash.equals(expectedPrev)) {
    return 'prev_hash_mismatch';
  }
  let computed: Buffer;
  try {
    computed = eventChainHash(row.prev_hash, envelopeOf(row));
  } catch {
    return 'unreadable_row';
  }
  return Buffer.isBuffer(row.hash) && computed.equals(row.hash) ? undefined : 'hash_mismatch';
}

/** The stored form of an approval: the members its schema names, nothing else. */
function storedApproval(approval: AdminApproval): AdminApproval {
  return {
    approverId: approval.approverId,
    credentialId: approval.credentialId,
    approverCreatedBy: {
      type: approval.approverCreatedBy.type,
      ...(approval.approverCreatedBy.id === undefined ? {} : { id: approval.approverCreatedBy.id }),
    },
    ...(approval.approvedAt === undefined ? {} : { approvedAt: approval.approvedAt }),
  };
}

function checkChainPoint(point: EventChainPoint): EventChainPoint {
  if (typeof point.seq !== 'bigint' || point.seq < 0n) {
    throw new TypeError('events: a chain point needs a seq, a bigint of 0 or more');
  }
  if (typeof point.hash !== 'string' || !SHA256_HEX.test(point.hash)) {
    throw new TypeError('events: a chain point needs its hash as 64 hex digits');
  }
  return { seq: point.seq, hash: point.hash.toLowerCase() };
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
  const batchSize = options.verifyBatchSize ?? DEFAULT_VERIFY_BATCH_SIZE;
  if (!Number.isSafeInteger(batchSize) || batchSize < 1) {
    throw new TypeError('createEventsRepository: verifyBatchSize must be a positive integer');
  }

  async function emit(tx: DbTransaction, event: UncheckedEvent): Promise<string> {
    const built = buildEvent(event, now());
    return built.row.category === 'admin' ? appendToChain(tx, built) : insertEvent(tx, built.row);
  }

  return {
    emit,

    async emitInOwnTransaction(event) {
      const built = buildEvent(event, now());
      if (built.row.category === 'admin') {
        return defaultDb.transaction((tx) => appendToChain(tx, built));
      }
      // One INSERT on the root database is a transaction of its own.
      return insertEvent(defaultDb, built.row);
    },

    async emitAdminEvent(tx, input: AdminEventInput) {
      if (!input.actor) {
        throw new TypeError('emitAdminEvent: an admin change needs the actor who made it');
      }
      const data = {
        operation: input.operation,
        target: { type: input.target.type, id: input.target.id },
        diff: buildAdminDiff(input.before, input.after, { secretFields: input.secretFields }),
        approvals: (input.approvals ?? []).map(storedApproval),
      };
      return emit(tx, {
        type: adminChangeApplied.type,
        realm: input.realm,
        actor: input.actor,
        ...(input.client === undefined ? {} : { client: input.client }),
        ...(input.request === undefined ? {} : { request: input.request }),
        data,
      });
    },

    async verifyChain(realmId, from): Promise<EventChainReport> {
      const realm = checkRealmId(realmId);
      const start = checkChainPoint(
        from ?? { seq: 0n, hash: EVENT_CHAIN_GENESIS_HASH.toString('hex') }
      );
      return defaultDb.transaction(
        async (tx) => {
          let expectedPrev: Buffer = Buffer.from(start.hash, 'hex');
          let after = start.seq;
          let rowsChecked = 0;
          let head: (EventChainPoint & { id: string }) | null = null;

          for (;;) {
            const { rows } = await tx.execute<ChainRow>(sql`
              select ${ENVELOPE_COLUMNS}, ${events.prevHash} as "prev_hash", ${events.hash} as "hash"
              from ${events}
              where ${events.realmId} = ${realm} and ${events.hash} is not null
                and ${events.seq} > ${after.toString()}::bigint
              order by ${events.seq}
              limit ${batchSize}
            `);
            for (const row of rows) {
              const seq = BigInt(row.seq);
              const reason = checkChainRow(row, expectedPrev);
              if (reason) {
                return {
                  ok: false,
                  realmId: realm,
                  from: start,
                  rowsChecked,
                  break: { id: row.id, seq, reason },
                };
              }
              rowsChecked += 1;
              expectedPrev = row.hash;
              head = { id: row.id, seq, hash: row.hash.toString('hex') };
            }
            if (rows.length < batchSize) break;
            after = BigInt(rows[rows.length - 1].seq);
          }
          return { ok: true, realmId: realm, from: start, rowsChecked, head };
        },
        { isolationLevel: 'repeatable read', accessMode: 'read only' }
      );
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
          select ${ENVELOPE_COLUMNS}
          from ${events}
          where ${where}
          order by ${events.xid}, ${events.seq}
          limit ${limit}
        ) as "page" on true
      `);

      const page = rows
        .filter((row): row is ReadRow & EnvelopeRow => row.seq !== null)
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
