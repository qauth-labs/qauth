/**
 * Real-Postgres integration tests for the delivery queue (issue #460).
 *
 * What only a database can prove: the fan-out writes one row per matching
 * destination and event, never skips an event an older transaction held
 * back, and starts a new realm at the horizon; two claims at once never take
 * the same row (`FOR UPDATE SKIP LOCKED`); a lease that runs out makes a row
 * due again; an outcome from a claim that lost its row writes nothing;
 * `minOffered` stops before the oldest unfinished event; deleting an event
 * deletes its rows; and a role holding only the delivery grants can do all of
 * it and nothing more.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type {
  Database,
  EmitEvent,
  EventDeliveriesRepository,
  EventDeliveryDestination,
  EventsRepository,
} from '../../types';
import { eventDeliveryGrantStatements } from '../events/delivery-grants';
import { decodeEventPosition } from '../events/position';
import {
  ATTEMPT_INTERRUPTED,
  createEventDeliveriesRepository,
} from './event-deliveries.repository';
import { createEventsRepository } from './events.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
const SIGNED_OUT = 'urn:qauth:event:user.signed_out:v1-rc.0';
const NOW = 1_800_000_000_000;
const LEASE = 60_000;
/** The route kinds the suite's fan-outs serve. */
const KINDS = ['test', 'other'];

function signedIn(realm: string): EmitEvent<'urn:qauth:event:user.signed_in:v1-rc.0'> {
  const userId = randomUUID();
  return {
    type: SIGNED_IN,
    realm,
    actor: { type: 'user', id: userId },
    subject: { type: 'user', id: userId },
    data: { method: 'password' },
  };
}

function signedOut(realm: string): EmitEvent<'urn:qauth:event:user.signed_out:v1-rc.0'> {
  const userId = randomUUID();
  return {
    type: SIGNED_OUT,
    realm,
    actor: { type: 'user', id: userId },
    subject: { type: 'user', id: userId },
    data: {},
  };
}

function destination(
  realmId: string,
  id: string,
  filters: Partial<EventDeliveryDestination> = {}
): EventDeliveryDestination {
  return { kind: 'test', id, realmId, ...filters };
}

/** A promise with its resolve function, to order steps across transactions. */
function gate(): { promise: Promise<void>; open: () => void } {
  let open: () => void = () => undefined;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

async function sqlState(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
  } catch (error) {
    let current: unknown = error;
    while (current && typeof current === 'object') {
      const candidate = current as { code?: unknown; cause?: unknown };
      if (typeof candidate.code === 'string' && /^[0-9A-Z]{5}$/.test(candidate.code)) {
        return candidate.code;
      }
      current = candidate.cause;
    }
  }
  return undefined;
}

describe('event deliveries integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let store: EventsRepository;
  let queue: EventDeliveriesRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    // A container of its own: a case below creates roles, which are
    // cluster-wide and outlive the database, so on a shared server their
    // fixed names would meet the next suite's.
    ctx = await setupIntegrationDb({ privateContainer: true });
    store = createEventsRepository(ctx.database.db);
    queue = createEventDeliveriesRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  function db(): Database {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.db;
  }

  /** Fan out once so each realm has a position, as a running role would have. */
  async function start(destinations: EventDeliveryDestination[]): Promise<void> {
    await queue.fanOut({ kinds: KINDS, destinations, now: NOW });
  }

  async function rows(): Promise<
    Array<{ destination_id: string; event_id: string; status: string; attempt_count: number }>
  > {
    const { rows: found } = await pool().query(
      `SELECT destination_id, event_id::text, status, attempt_count
         FROM event_deliveries ORDER BY event_xid, event_seq, destination_id`
    );
    return found;
  }

  describe('the fan-out', () => {
    it('starts a new realm at the horizon, then writes one row per matching destination and event', async () => {
      const realm = randomUUID();
      const before = await store.emitInOwnTransaction(signedIn(realm));
      const destinations = [
        destination(realm, 'all'),
        destination(realm, 'sign-ins', { types: [SIGNED_IN] }),
        destination(realm, 'admin-only', { categories: ['admin'] }),
        destination(realm, 'none', { types: [] }),
      ];

      expect(await queue.fanOut({ kinds: KINDS, destinations, now: NOW })).toMatchObject({
        realms: 1,
        events: 0,
        deliveries: 0,
      });
      const signIn = await store.emitInOwnTransaction(signedIn(realm));
      const signOut = await store.emitInOwnTransaction(signedOut(realm));
      expect(await queue.fanOut({ kinds: KINDS, destinations, now: NOW })).toMatchObject({
        realms: 1,
        events: 2,
        deliveries: 3,
      });

      expect(await rows()).toEqual([
        { destination_id: 'all', event_id: signIn, status: 'pending', attempt_count: 0 },
        { destination_id: 'sign-ins', event_id: signIn, status: 'pending', attempt_count: 0 },
        { destination_id: 'all', event_id: signOut, status: 'pending', attempt_count: 0 },
      ]);
      // The event before the realm's first fan-out is not delivered.
      expect((await rows()).map((row) => row.event_id)).not.toContain(before);
    });

    it('writes no row twice, even when the position is moved back', async () => {
      const realm = randomUUID();
      const destinations = [destination(realm, 'a')];
      await start(destinations);
      await store.emitInOwnTransaction(signedIn(realm));
      await queue.fanOut({ kinds: KINDS, destinations, now: NOW });
      await pool().query(`UPDATE event_delivery_positions SET xid = '0', seq = 0`);

      expect(await queue.fanOut({ kinds: KINDS, destinations, now: NOW })).toMatchObject({
        events: 1,
        deliveries: 0,
      });
      expect(await rows()).toHaveLength(1);
    });

    it('never skips an event an older open transaction held back', async () => {
      const realm = randomUUID();
      const destinations = [destination(realm, 'a')];
      await start(destinations);

      const started = gate();
      const release = gate();
      let late = '';
      const open = db().transaction(async (tx) => {
        late = await store.emit(tx, signedIn(realm));
        started.open();
        await release.promise;
      });
      await started.promise;
      let after: string;
      try {
        // Committed after the open transaction began: not final until it ends.
        after = await store.emitInOwnTransaction(signedIn(realm));
        await queue.fanOut({ kinds: KINDS, destinations, now: NOW });
        expect(await rows()).toEqual([]);
      } finally {
        release.open();
        await open;
      }
      await queue.fanOut({ kinds: KINDS, destinations, now: NOW });
      expect(new Set((await rows()).map((row) => row.event_id))).toEqual(new Set([late, after]));
    });

    it('reads in pages, and keeps realms apart', async () => {
      const realm = randomUUID();
      const other = randomUUID();
      const destinations = [destination(realm, 'a'), destination(other, 'b')];
      await start(destinations);
      for (let i = 0; i < 5; i += 1) await store.emitInOwnTransaction(signedIn(realm));
      await store.emitInOwnTransaction(signedIn(other));

      expect(
        await queue.fanOut({
          kinds: KINDS,
          destinations,
          now: NOW,
          pageSize: 2,
          maxPagesPerRealm: 2,
        })
      ).toMatchObject({ realms: 2, events: 5, more: true });
      expect(
        await queue.fanOut({ kinds: KINDS, destinations, now: NOW, pageSize: 2 })
      ).toMatchObject({
        events: 1,
        more: false,
      });
      const byDestination = await pool().query(
        `SELECT destination_id, realm_id::text, count(*)::int AS n FROM event_deliveries
          GROUP BY 1, 2 ORDER BY 1`
      );
      expect(byDestination.rows).toEqual([
        { destination_id: 'a', realm_id: realm, n: 5 },
        { destination_id: 'b', realm_id: other, n: 1 },
      ]);
    });

    it('forgets the position of a realm whose last destination went', async () => {
      const realm = randomUUID();
      await start([destination(realm, 'a')]);
      await store.emitInOwnTransaction(signedIn(realm));
      await queue.fanOut({ kinds: KINDS, destinations: [], now: NOW });
      expect((await pool().query('SELECT * FROM event_delivery_positions')).rows).toEqual([]);

      // Back with a destination: it starts at the horizon, not at the old position.
      await start([destination(realm, 'a')]);
      await queue.fanOut({ kinds: KINDS, destinations: [destination(realm, 'a')], now: NOW });
      expect(await rows()).toEqual([]);
    });

    it('keeps one position per route kind, and touches only the kinds a node serves', async () => {
      const realm = randomUUID();
      const both = [destination(realm, 'w'), { ...destination(realm, 's'), kind: 'other' }];
      await queue.fanOut({ kinds: KINDS, destinations: both, now: NOW });
      const positions = async () =>
        (
          await pool().query(
            `SELECT destination_kind, xid::text, seq::text FROM event_delivery_positions
              ORDER BY destination_kind`
          )
        ).rows;
      expect((await positions()).map((row) => row.destination_kind)).toEqual(['other', 'test']);

      // A node that serves only `test`, with no destination of it, as an
      // older release during a rollout might: it forgets its own kind only.
      await queue.fanOut({ kinds: ['test'], destinations: [], now: NOW });
      expect((await positions()).map((row) => row.destination_kind)).toEqual(['other']);
      // And a node with no route touches nothing.
      await queue.fanOut({ kinds: [], destinations: [], now: NOW });
      expect((await positions()).map((row) => row.destination_kind)).toEqual(['other']);

      // A node that serves only `test` moves the `test` position, never the other one.
      await queue.fanOut({ kinds: ['test'], destinations: [both[0]], now: NOW });
      const before = await positions();
      const signIn = await store.emitInOwnTransaction(signedIn(realm));
      await queue.fanOut({ kinds: ['test'], destinations: [both[0]], now: NOW });
      const after = await positions();
      expect(after.find((row) => row.destination_kind === 'other')).toEqual(
        before.find((row) => row.destination_kind === 'other')
      );
      expect(await rows()).toEqual([
        { destination_id: 'w', event_id: signIn, status: 'pending', attempt_count: 0 },
      ]);
      // The other kind's node still delivers the event to its destination.
      await queue.fanOut({ kinds: ['other'], destinations: [both[1]], now: NOW });
      expect((await rows()).map((row) => row.destination_id).sort()).toEqual(['s', 'w']);
    });

    it('refuses a destination of a kind the request does not serve', async () => {
      await expect(
        queue.fanOut({
          kinds: ['test'],
          destinations: [{ ...destination(randomUUID(), 'x'), kind: 'other' }],
          now: NOW,
        })
      ).rejects.toThrow(TypeError);
    });

    it('leaves a realm another worker is fanning out to that worker', async () => {
      const realm = randomUUID();
      await start([destination(realm, 'a')]);
      await store.emitInOwnTransaction(signedIn(realm));
      const holder = await pool().connect();
      try {
        await holder.query('BEGIN');
        await holder.query(
          `SELECT pg_advisory_xact_lock(hashtextextended('qauth:events:fan-out:' || $1::uuid::text || ':test', 0))`,
          [realm]
        );
        expect(
          await queue.fanOut({ kinds: KINDS, destinations: [destination(realm, 'a')], now: NOW })
        ).toMatchObject({ realms: 0, skippedRealms: 1, deliveries: 0 });
        await holder.query('ROLLBACK');
      } finally {
        holder.release();
      }
      expect(
        await queue.fanOut({ kinds: KINDS, destinations: [destination(realm, 'a')], now: NOW })
      ).toMatchObject({ realms: 1, deliveries: 1 });
    });
  });

  describe('claims', () => {
    async function queued(destinations: string[], count: number): Promise<string> {
      const realm = randomUUID();
      const list = destinations.map((id) => destination(realm, id));
      await start(list);
      for (let i = 0; i < count; i += 1) await store.emitInOwnTransaction(signedIn(realm));
      await queue.fanOut({ kinds: KINDS, destinations: list, now: NOW });
      return realm;
    }

    it('finds the destinations with work due', async () => {
      await queued(['a', 'b', 'c'], 1);
      await pool().query(
        `UPDATE event_deliveries SET next_attempt_at = $1 WHERE destination_id = 'b'`,
        [NOW + 1]
      );
      expect(await queue.dueDestinations(['test', 'other'], NOW)).toEqual([
        { kind: 'test', id: 'a' },
        { kind: 'test', id: 'c' },
      ]);
    });

    it('takes each row once when two claims run at the same time', async () => {
      await queued(['a'], 20);
      const request = {
        picks: [{ kind: 'test', id: 'a', limit: 15 }],
        now: NOW,
        leaseMs: LEASE,
        maxAttempts: 5,
      };
      const [first, second] = await Promise.all([queue.claim(request), queue.claim(request)]);

      const ids = [...first, ...second].map((claim) => claim.id);
      expect(ids).toHaveLength(20);
      expect(new Set(ids).size).toBe(20);
      expect(first.every((claim) => claim.attempt === 1 && claim.lockedUntil === NOW + LEASE)).toBe(
        true
      );
    });

    it('hands over the event with its stable id', async () => {
      const realm = await queued(['a'], 1);
      const [claim] = await queue.claim({
        picks: [{ kind: 'test', id: 'a', limit: 1 }],
        now: NOW,
        leaseMs: LEASE,
        maxAttempts: 5,
      });
      expect(claim.event).toMatchObject({ id: claim.eventId, realm, type: SIGNED_IN });
      expect(claim.realmId).toBe(realm);
    });

    it('makes a row due again when its lease runs out, and refuses the old claim its outcome', async () => {
      await queued(['a'], 1);
      const pick = { picks: [{ kind: 'test', id: 'a', limit: 5 }], leaseMs: LEASE, maxAttempts: 5 };
      const [first] = await queue.claim({ ...pick, now: NOW });
      expect(await queue.claim({ ...pick, now: NOW + LEASE - 1 })).toEqual([]);
      expect(await queue.dueDestinations(['test'], NOW + LEASE - 1)).toEqual([]);

      const [second] = await queue.claim({ ...pick, now: NOW + LEASE });
      expect(second).toMatchObject({ id: first.id, eventId: first.eventId, attempt: 2 });

      expect(await queue.record(first, { result: 'delivered', statusCode: 200 }, NOW + LEASE)).toBe(
        false
      );
      expect(
        await queue.record(second, { result: 'delivered', statusCode: 204 }, NOW + LEASE)
      ).toBe(true);
      const [row] = await queue.listForEvent(first.eventId);
      expect(row).toMatchObject({
        status: 'delivered',
        attemptCount: 2,
        lastStatusCode: 204,
        lockedUntil: null,
        finishedAt: NOW + LEASE,
      });
    });

    it('schedules a retry, and ends failed with the error class', async () => {
      await queued(['a'], 1);
      const pick = { picks: [{ kind: 'test', id: 'a', limit: 5 }], leaseMs: LEASE, maxAttempts: 5 };
      const [first] = await queue.claim({ ...pick, now: NOW });
      await queue.record(
        first,
        {
          result: 'retry',
          nextAttemptAt: NOW + 30_000,
          statusCode: 503,
          errorClass: 'http_status',
        },
        NOW + 10
      );
      expect(await queue.claim({ ...pick, now: NOW + 29_999 })).toEqual([]);
      const [second] = await queue.claim({ ...pick, now: NOW + 30_000 });
      await queue.record(
        second,
        { result: 'failed', errorClass: 'destination_gone' },
        NOW + 30_001
      );

      expect((await queue.listForEvent(first.eventId))[0]).toMatchObject({
        status: 'failed',
        attemptCount: 2,
        lastStatusCode: null,
        lastErrorClass: 'destination_gone',
        finishedAt: NOW + 30_001,
      });
      expect(await queue.claim({ ...pick, now: NOW + 10 * LEASE })).toEqual([]);
    });

    it('gives back the attempt of a held row, keeps its last failure, and makes it due again', async () => {
      await queued(['a'], 1);
      const pick = { picks: [{ kind: 'test', id: 'a', limit: 5 }], leaseMs: LEASE, maxAttempts: 2 };
      const [first] = await queue.claim({ ...pick, now: NOW });
      await queue.record(
        first,
        { result: 'retry', nextAttemptAt: NOW + 10, statusCode: 503, errorClass: 'http_status' },
        NOW + 1
      );
      // Held on its last attempt, again and again: never used up.
      let at = NOW + 10;
      for (let hold = 0; hold < 3; hold += 1) {
        const [claim] = await queue.claim({ ...pick, now: at });
        expect(claim.attempt).toBe(2);
        expect(await queue.record(claim, { result: 'hold', nextAttemptAt: at + 30_000 }, at)).toBe(
          true
        );
        expect((await queue.listForEvent(first.eventId))[0]).toMatchObject({
          status: 'pending',
          attemptCount: 1,
          lastStatusCode: 503,
          lastErrorClass: 'http_status',
          lockedUntil: null,
          nextAttemptAt: at + 30_000,
        });
        expect(await queue.claim({ ...pick, now: at + 29_999 })).toEqual([]);
        // A claim that lost its row holds nothing.
        expect(await queue.record(claim, { result: 'hold', nextAttemptAt: at }, at)).toBe(false);
        at += 30_000;
      }

      const [last] = await queue.claim({ ...pick, now: at });
      expect(last.attempt).toBe(2);
      await queue.record(last, { result: 'delivered', statusCode: 202 }, at);
      expect((await queue.listForEvent(first.eventId))[0]).toMatchObject({
        status: 'delivered',
        attemptCount: 2,
        lastErrorClass: null,
      });
    });

    it('gives a released row back at once, the attempt counted', async () => {
      await queued(['a'], 1);
      const pick = { picks: [{ kind: 'test', id: 'a', limit: 5 }], leaseMs: LEASE, maxAttempts: 5 };
      const [first] = await queue.claim({ ...pick, now: NOW });
      expect(await queue.release([first], NOW + 5)).toBe(1);
      expect(await queue.record(first, { result: 'delivered' }, NOW + 6)).toBe(false);

      const [second] = await queue.claim({ ...pick, now: NOW + 5 });
      expect(second.attempt).toBe(2);
      expect((await queue.listForEvent(first.eventId))[0].lastErrorClass).toBe(ATTEMPT_INTERRUPTED);
    });

    it('ends a row failed when its last attempt was interrupted', async () => {
      await queued(['a'], 1);
      const pick = { picks: [{ kind: 'test', id: 'a', limit: 5 }], leaseMs: LEASE, maxAttempts: 2 };
      await queue.claim({ ...pick, now: NOW });
      const [second] = await queue.claim({ ...pick, now: NOW + LEASE });
      expect(second.attempt).toBe(2);

      expect(await queue.claim({ ...pick, now: NOW + 2 * LEASE })).toEqual([]);
      expect((await queue.listForEvent(second.eventId))[0]).toMatchObject({
        status: 'failed',
        attemptCount: 2,
        lastErrorClass: ATTEMPT_INTERRUPTED,
        lockedUntil: null,
        finishedAt: NOW + 2 * LEASE,
      });
    });

    it('leaves an event stored in a later layout to a node that reads it', async () => {
      await queued(['a'], 1);
      await pool().query('ALTER TABLE events DISABLE TRIGGER events_no_update');
      try {
        await pool().query('UPDATE events SET schema_version = 2');
      } finally {
        await pool().query('ALTER TABLE events ENABLE TRIGGER events_no_update');
      }
      expect(
        await queue.claim({
          picks: [{ kind: 'test', id: 'a', limit: 1 }],
          now: NOW,
          leaseMs: LEASE,
          maxAttempts: 5,
        })
      ).toEqual([]);
      expect(await rows()).toEqual([
        expect.objectContaining({ status: 'pending', attempt_count: 0 }),
      ]);
    });

    it('lives as long as its event', async () => {
      await queued(['a', 'b'], 1);
      expect(await rows()).toHaveLength(2);
      await pool().query('DELETE FROM events');
      expect(await rows()).toEqual([]);
    });
  });

  describe('minOffered, the pending count and the lag', () => {
    it('stops before the oldest unfinished event, and moves on when it finishes', async () => {
      const realm = randomUUID();
      const destinations = [destination(realm, 'a')];
      await start(destinations);
      const initial = decodeEventPosition(await queue.minOffered(realm));

      await store.emitInOwnTransaction(signedIn(realm));
      await store.emitInOwnTransaction(signedIn(realm));
      await queue.fanOut({ kinds: KINDS, destinations, now: NOW });
      const [oldest] = (
        await pool().query(
          `SELECT xid::text, seq::text FROM events WHERE realm_id = $1 ORDER BY xid, seq LIMIT 1`,
          [realm]
        )
      ).rows;
      expect(decodeEventPosition(await queue.minOffered(realm))).toEqual({
        realmId: realm,
        xid: BigInt(oldest.xid),
        seq: BigInt(oldest.seq) - 1n,
      });
      expect(BigInt(oldest.xid)).toBeGreaterThanOrEqual(initial.xid);

      const claims = await queue.claim({
        picks: [{ kind: 'test', id: 'a', limit: 5 }],
        now: NOW,
        leaseMs: LEASE,
        maxAttempts: 5,
      });
      for (const claim of claims) await queue.record(claim, { result: 'delivered' }, NOW);
      const position = (
        await pool().query(`SELECT xid::text, seq::text FROM event_delivery_positions`)
      ).rows[0];
      expect(decodeEventPosition(await queue.minOffered(realm))).toEqual({
        realmId: realm,
        xid: BigInt(position.xid),
        seq: BigInt(position.seq),
      });
    });

    it("is at most the lowest position of the realm's kinds", async () => {
      const realm = randomUUID();
      const other = { ...destination(realm, 's'), kind: 'other' };
      await queue.fanOut({
        kinds: KINDS,
        destinations: [destination(realm, 'w'), other],
        now: NOW,
      });
      await store.emitInOwnTransaction(signedIn(realm));
      // Only `test` reads on; `other` stays behind.
      await queue.fanOut({ kinds: ['test'], destinations: [destination(realm, 'w')], now: NOW });
      const claims = await queue.claim({
        picks: [{ kind: 'test', id: 'w', limit: 5 }],
        now: NOW,
        leaseMs: LEASE,
        maxAttempts: 5,
      });
      for (const claim of claims) await queue.record(claim, { result: 'delivered' }, NOW);
      const { rows: behind } = await pool().query(
        `SELECT xid::text, seq::text FROM event_delivery_positions WHERE destination_kind = 'other'`
      );
      expect(decodeEventPosition(await queue.minOffered(realm))).toEqual({
        realmId: realm,
        xid: BigInt(behind[0].xid),
        seq: BigInt(behind[0].seq),
      });
    });

    it('is the horizon for a realm without destinations', async () => {
      const realm = randomUUID();
      await store.emitInOwnTransaction(signedIn(realm));
      const { rows: found } = await pool().query(
        `SELECT pg_snapshot_xmin(pg_current_snapshot())::text AS horizon,
                (SELECT max(xid)::text FROM events) AS last`
      );
      const offered = decodeEventPosition(await queue.minOffered(realm));
      expect(offered.seq).toBe(0n);
      expect(offered.xid).toBeGreaterThan(BigInt(found[0].last));
      expect(offered.xid).toBeLessThanOrEqual(BigInt(found[0].horizon));
    });

    it('counts pending deliveries by kind and measures the oldest one waiting', async () => {
      const realm = randomUUID();
      const destinations = [destination(realm, 'a'), { ...destination(realm, 'b'), kind: 'other' }];
      await start(destinations);
      expect(await queue.pendingByKind()).toEqual({});
      expect(await queue.deliveryLagSeconds(NOW)).toBe(0);

      await store.emitInOwnTransaction(signedIn(realm));
      const [{ time }] = (await pool().query('SELECT time::text FROM events')).rows;
      // Not fanned out yet: the lag counts it already.
      expect(await queue.deliveryLagSeconds(Number(time) + 1500)).toBe(1.5);

      await queue.fanOut({ kinds: KINDS, destinations, now: NOW });
      expect(await queue.pendingByKind()).toEqual({ test: 1, other: 1 });
      expect(await queue.deliveryLagSeconds(Number(time) + 2500)).toBe(2.5);
    });
  });

  describe('a role holding only the delivery grants', () => {
    const ROLE = 'qauth_event_delivery';
    let delivery: Pool | undefined;
    let deliveryQueue: EventDeliveriesRepository;

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      await pool().query(`CREATE ROLE ${ROLE} LOGIN PASSWORD '${ROLE}'`);
      await pool().query(`GRANT USAGE ON SCHEMA public TO ${ROLE}`);
      for (let i = 0; i < 2; i += 1) {
        for (const statement of eventDeliveryGrantStatements(ROLE)) await pool().query(statement);
      }
      const url = new URL(ctx.connectionString);
      url.username = ROLE;
      url.password = ROLE;
      delivery = new Pool({ connectionString: url.toString(), max: 4 });
      deliveryQueue = createEventDeliveriesRepository(drizzle(delivery) as unknown as Database);
    });

    afterAll(async () => {
      await delivery?.end();
    });

    it('fans out, claims, records, releases and reads its metrics', async () => {
      const realm = randomUUID();
      const destinations = [destination(realm, 'a')];
      await deliveryQueue.fanOut({ kinds: KINDS, destinations, now: NOW });
      await store.emitInOwnTransaction(signedIn(realm));
      expect(await deliveryQueue.fanOut({ kinds: KINDS, destinations, now: NOW })).toMatchObject({
        deliveries: 1,
      });

      expect(await deliveryQueue.dueDestinations(['test'], NOW)).toEqual([
        { kind: 'test', id: 'a' },
      ]);
      const pick = { picks: [{ kind: 'test', id: 'a', limit: 1 }], leaseMs: LEASE, maxAttempts: 5 };
      const [first] = await deliveryQueue.claim({ ...pick, now: NOW });
      expect(await deliveryQueue.release([first], NOW)).toBe(1);
      const [second] = await deliveryQueue.claim({ ...pick, now: NOW });
      expect(await deliveryQueue.record(second, { result: 'delivered' }, NOW)).toBe(true);

      expect(await deliveryQueue.pendingByKind()).toEqual({});
      expect(await deliveryQueue.deliveryLagSeconds(NOW)).toBeGreaterThanOrEqual(0);
      expect(decodeEventPosition(await deliveryQueue.minOffered(realm)).realmId).toBe(realm);
      expect(await deliveryQueue.listForEvent(first.eventId)).toHaveLength(1);
      await deliveryQueue.fanOut({ kinds: KINDS, destinations: [], now: NOW });
    });

    it('cannot write or delete events, delete deliveries, or read another table', async () => {
      const realm = randomUUID();
      await store.emitInOwnTransaction(signedIn(realm));
      for (const statement of [
        `INSERT INTO events (id, realm_id, category, type, time, data, schema_version)
           VALUES (uuidv7(), '${realm}', 'user', 'x', 0, '{}', 1)`,
        `DELETE FROM events`,
        `DELETE FROM event_deliveries`,
        `SELECT * FROM realm_keys`,
        `SELECT * FROM sessions`,
        `SELECT * FROM users`,
      ]) {
        expect(await sqlState(delivery?.query(statement) ?? Promise.resolve()), statement).toBe(
          '42501'
        );
      }
    });
  });
});
