import { EVENT_CATEGORIES, type EventCategory } from '@qauth-labs/shared-events';
import { type EventRetentionPolicy, eventRetentionProblems } from '@qauth-labs/shared-validation';
import { sql } from 'drizzle-orm';

import type {
  Database,
  DbTransaction,
  EventChainPoint,
  EventRetentionBatch,
  EventRetentionBatchRequest,
  EventRetentionChainBreak,
  EventRetentionRepository,
  OldestEventTimes,
  RealmEventRetention,
} from '../../types';
import { EVENT_CHAIN_GENESIS_HASH } from '../events/chain';
import {
  decodeEventPosition,
  encodeEventPosition,
  type EventPositionParts,
} from '../events/position';
import { realms } from '../schema/core';
import { eventChainAnchors, events } from '../schema/events';
import { offeredPosition } from './event-deliveries.repository';
import { type ChainRow, checkChainRow, ENVELOPE_COLUMNS } from './events.repository';

/**
 * The prefix of a realm's retention lock key. The lock is
 * `pg_try_advisory_xact_lock(hashtextextended(prefix || realm_id, 0))`, a key
 * no other lock of QAuth uses.
 */
export const EVENT_RETENTION_LOCK_PREFIX = 'qauth:events:retention:';

/** The most rows one batch may delete. */
export const EVENT_RETENTION_BATCH_MAX = 10_000;

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function checkRealmId(realmId: string, caller: string): string {
  if (typeof realmId !== 'string' || !UUID_PATTERN.test(realmId)) {
    throw new TypeError(`eventRetention.${caller}: a realm id must be a UUID`);
  }
  return realmId.toLowerCase();
}

function checkTime(value: number, what: string): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`eventRetention.deleteBatch: ${what} must be epoch milliseconds`);
  }
  return value;
}

/**
 * The distinct realms of `events`, as a recursive CTE: a loose index scan,
 * one descent per realm, so it costs as many index probes as there are
 * realms, not rows.
 */
const REALMS_WITH_EVENTS = sql`with recursive "seen" as (
    (select ${events.realmId} as "realm_id" from ${events} order by ${events.realmId} limit 1)
    union all
    select (
      select ${events.realmId} from ${events}
      where ${events.realmId} > "seen"."realm_id"
      order by ${events.realmId} limit 1
    ) from "seen" where "seen"."realm_id" is not null
  )`;

/**
 * Delete up to `limit` of a realm's rows of one category that sit outside
 * the admin chain (every user row, and admin rows written before migration
 * 0032), oldest first.
 */
async function deleteUnchained(
  tx: DbTransaction,
  realmId: string,
  category: EventCategory,
  before: number,
  through: EventPositionParts,
  limit: number
): Promise<number> {
  const result = await tx.execute(sql`
    delete from ${events} where ${events.seq} in (
      select ${events.seq} from ${events}
      where ${events.realmId} = ${realmId} and ${events.category} = ${category}
        and ${events.hash} is null
        and ${events.time} < ${before}
        and (${events.xid}, ${events.seq}) <= (${through.xid.toString()}::xid8, ${through.seq.toString()}::bigint)
      order by ${events.time}
      limit ${limit}
    )
  `);
  return result.rowCount ?? 0;
}

/**
 * Delete the start of a realm's admin chain: up to `limit` chained rows in
 * `seq` order, stopping at the first that is too young, not yet offered,
 * the chain's head, or does not verify against the row before it (the
 * stored anchor, or the genesis hash, for the first). The last row deleted
 * becomes the anchor, written before the delete in the same transaction.
 */
async function deleteChainStart(
  tx: DbTransaction,
  realmId: string,
  before: number,
  through: EventPositionParts,
  limit: number,
  now: number
): Promise<{
  deleted: number;
  full: boolean;
  anchor: EventChainPoint | null;
  chainBreak: EventRetentionChainBreak | null;
}> {
  const [stored] = await tx
    .select({ seq: eventChainAnchors.seq, hash: eventChainAnchors.hash })
    .from(eventChainAnchors)
    .where(sql`${eventChainAnchors.realmId} = ${realmId}`);
  const { rows: headRows } = await tx.execute<{ seq: string }>(sql`
    select ${events.seq}::text as "seq" from ${events}
    where ${events.realmId} = ${realmId} and ${events.hash} is not null
    order by ${events.seq} desc limit 1
  `);
  const head = headRows[0] === undefined ? undefined : BigInt(headRows[0].seq);
  const { rows } = await tx.execute<ChainRow>(sql`
    select ${ENVELOPE_COLUMNS}, ${events.prevHash} as "prev_hash", ${events.hash} as "hash"
    from ${events}
    where ${events.realmId} = ${realmId} and ${events.hash} is not null
    order by ${events.seq}
    limit ${limit}
  `);

  let expectedPrev: Buffer = stored?.hash ?? EVENT_CHAIN_GENESIS_HASH;
  let chainBreak: EventRetentionChainBreak | null = null;
  const doomed: ChainRow[] = [];
  for (const row of rows) {
    const seq = BigInt(row.seq);
    const xid = BigInt(row.xid);
    const offered = xid < through.xid || (xid === through.xid && seq <= through.seq);
    // The head stays: the next admin event follows it, and a chain whose
    // every row was deleted would start again at the genesis hash.
    if (seq === head || Number(row.time) >= before || !offered) break;
    const reason = checkChainRow(row, expectedPrev);
    if (reason) {
      // A changed or cut row is evidence: it stays for verifyChain to report.
      chainBreak = { id: row.id, seq, reason };
      break;
    }
    doomed.push(row);
    expectedPrev = row.hash;
  }
  if (doomed.length === 0) return { deleted: 0, full: false, anchor: null, chainBreak };

  const last = doomed[doomed.length - 1];
  const anchor: EventChainPoint = { seq: BigInt(last.seq), hash: last.hash.toString('hex') };
  // Forward only: a smaller seq would make rows already deleted the start
  // again. The retention lock rules a concurrent job out, so this refuses
  // only a table someone else changed.
  const moved = await tx.execute(sql`
    insert into ${eventChainAnchors} (realm_id, seq, hash, updated_at)
    values (${realmId}::uuid, ${anchor.seq.toString()}::bigint, ${last.hash}, ${now})
    on conflict (realm_id) do update
      set seq = excluded.seq, hash = excluded.hash, updated_at = excluded.updated_at
      where ${eventChainAnchors.seq} < excluded.seq
  `);
  if ((moved.rowCount ?? 0) !== 1) {
    throw new Error(
      `eventRetention: the chain anchor of realm ${realmId} is already past seq ${anchor.seq}; nothing was deleted`
    );
  }
  const result = await tx.execute(sql`
    delete from ${events}
    where ${events.realmId} = ${realmId}
      and ${events.seq} = any(${sql.param(doomed.map((row) => row.seq))}::bigint[])
  `);
  const deleted = result.rowCount ?? 0;
  if (deleted !== doomed.length) {
    throw new Error(
      `eventRetention: deleted ${deleted} of ${doomed.length} admin rows of realm ${realmId}; nothing was deleted`
    );
  }
  return { deleted, full: deleted === limit, anchor, chainBreak };
}

/**
 * Factory for the retention job's repository (ADR-020 §3, ADR-019 Decision 7,
 * issue #536). See {@link EventRetentionRepository} for the rules.
 *
 * @param db - The database, connected as the retention role
 *   (`eventRetentionGrantStatements`).
 * @returns Repository implementing {@link EventRetentionRepository}
 */
export function createEventRetentionRepository(db: Database): EventRetentionRepository {
  return {
    async realms(fallback: EventRetentionPolicy): Promise<RealmEventRetention[]> {
      const problems = eventRetentionProblems(fallback);
      if (problems.length > 0) {
        throw new TypeError(`eventRetention.realms: ${problems.join('; ')}`);
      }
      const { rows } = await db.execute<{
        realm_id: string;
        user_days: number | null;
        admin_days: number | null;
      }>(sql`
        ${REALMS_WITH_EVENTS}
        select "seen"."realm_id"::text as "realm_id",
          ${realms.userEventRetentionDays} as "user_days",
          ${realms.adminEventRetentionDays} as "admin_days"
        from "seen" left join ${realms} on ${realms.id} = "seen"."realm_id"
        where "seen"."realm_id" is not null
        order by "seen"."realm_id"
      `);
      return rows.map((row) => ({
        realmId: row.realm_id,
        realmExists: row.user_days !== null,
        userEventRetentionDays: row.user_days ?? fallback.userEventRetentionDays,
        adminEventRetentionDays: row.admin_days ?? fallback.adminEventRetentionDays,
      }));
    },

    async offeredThrough(realmId, served) {
      const realm = checkRealmId(realmId, 'offeredThrough');
      return encodeEventPosition(await offeredPosition(db, realm, served));
    },

    async deleteBatch(request: EventRetentionBatchRequest): Promise<EventRetentionBatch> {
      const realm = checkRealmId(request.realmId, 'deleteBatch');
      if (!(EVENT_CATEGORIES as readonly string[]).includes(request.category)) {
        throw new TypeError('eventRetention.deleteBatch: the category must be user or admin');
      }
      const before = checkTime(request.before, 'before');
      const now = checkTime(request.now, 'now');
      if (
        !Number.isSafeInteger(request.limit) ||
        request.limit < 1 ||
        request.limit > EVENT_RETENTION_BATCH_MAX
      ) {
        throw new TypeError(
          `eventRetention.deleteBatch: the limit must be an integer from 1 to ${EVENT_RETENTION_BATCH_MAX}`
        );
      }
      const through = decodeEventPosition(request.through);
      if (through.realmId !== realm) {
        throw new TypeError('eventRetention.deleteBatch: the position belongs to another realm');
      }
      const limit = request.limit;

      return db.transaction(
        async (tx): Promise<EventRetentionBatch> => {
          const { rows: lock } = await tx.execute<{ locked: boolean }>(sql`
            select pg_try_advisory_xact_lock(hashtextextended(${EVENT_RETENTION_LOCK_PREFIX}::text || (${realm})::uuid::text, 0)) as "locked"
          `);
          if (lock[0]?.locked !== true) return { status: 'busy' };

          const unchained = await deleteUnchained(
            tx,
            realm,
            request.category,
            before,
            through,
            limit
          );
          if (request.category === 'user' || unchained === limit) {
            return {
              status: 'done',
              deleted: unchained,
              more: unchained === limit,
              anchor: null,
              chainBreak: null,
            };
          }
          const chain = await deleteChainStart(tx, realm, before, through, limit - unchained, now);
          return {
            status: 'done',
            deleted: unchained + chain.deleted,
            more: chain.full,
            anchor: chain.anchor,
            chainBreak: chain.chainBreak,
          };
        },
        { isolationLevel: 'read committed' }
      );
    },

    async oldestEventTimes(): Promise<OldestEventTimes> {
      // Per realm, the first row of the category in idx_events_retention,
      // then the oldest of those: two descents per realm.
      const { rows } = await db.execute<{ category: EventCategory; oldest: string | null }>(sql`
        ${REALMS_WITH_EVENTS}
        select "category"."name" as "category", (
          select min("first"."time") from "seen" cross join lateral (
            select ${events.time} as "time" from ${events}
            where ${events.realmId} = "seen"."realm_id" and ${events.category} = "category"."name"
            order by ${events.time}
            limit 1
          ) as "first"
          where "seen"."realm_id" is not null
        )::text as "oldest"
        from (values ('user'), ('admin')) as "category"("name")
      `);
      const times: Record<EventCategory, number | null> = { user: null, admin: null };
      for (const row of rows) {
        times[row.category] = row.oldest === null ? null : Number(row.oldest);
      }
      return times;
    },
  };
}
