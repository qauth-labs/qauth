/**
 * Real-Postgres integration tests for event retention (issue #536).
 *
 * What only a database can prove: a realm's events past its retention are
 * deleted, oldest first and in batches, and the younger ones stay; an event
 * stays while an enabled destination has not finished it, and a disabled one
 * does not hold it; the admin chain loses only its start, never its head,
 * and verifies from the anchor retention keeps, which breaks when changed;
 * a row that breaks the chain is never pruned away; two job instances at
 * once delete each row once; and only a role holding the retention grants
 * can delete from `events`, while that role can do all of the job's work.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { randomUUID } from 'node:crypto';

import type { EventCategory } from '@qauth-labs/shared-events';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { DAY_MS, type EventRetentionPolicy } from '@qauth-labs/shared-validation';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool, type PoolClient } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type {
  AdminEventInput,
  Database,
  DbTransaction,
  EmitEvent,
  EventDeliveriesRepository,
  EventRetentionRepository,
  EventsRepository,
  OfferedDestinations,
} from '../../types';
import { eventDeliveryGrantStatements } from '../events/delivery-grants';
import { eventsWriterGrantStatements } from '../events/grants';
import { eventRetentionGrantStatements } from '../events/retention-grants';
import { createEventDeliveriesRepository } from './event-deliveries.repository';
import { createEventRetentionRepository } from './event-retention.repository';
import { createEventsRepository } from './events.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

const NOW = 1_800_000_000_000;
const LEASE = 60_000;
const ADMIN_ID = '0192f1c4-4444-7000-8000-000000000004';
const POLICY: EventRetentionPolicy = { userEventRetentionDays: 90, adminEventRetentionDays: 365 };

function signedIn(realm: string): EmitEvent<'urn:qauth:event:user.signed_in:v1-rc.0'> {
  const userId = randomUUID();
  return {
    type: 'urn:qauth:event:user.signed_in:v1-rc.0',
    realm,
    actor: { type: 'user', id: userId },
    subject: { type: 'user', id: userId },
    data: { method: 'password' },
  };
}

function change(realm: string): AdminEventInput {
  return {
    realm,
    actor: { type: 'user', id: ADMIN_ID },
    operation: 'realms.mail.write',
    target: { type: 'realm', id: realm },
    before: { fromName: 'QAuth' },
    after: { fromName: `Ops ${randomUUID()}` },
  };
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

describe('event retention integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  /** The time the next event is written at. */
  let at = NOW;
  let store: EventsRepository;
  let queue: EventDeliveriesRepository;
  let retention: EventRetentionRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    store = createEventsRepository(ctx.database.db, { now: () => at });
    queue = createEventDeliveriesRepository(ctx.database.db);
    retention = createEventRetentionRepository(ctx.database.db);
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
    at = NOW;
  });

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  function db(): Database {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.db;
  }

  async function userEventAt(realm: string, daysAgo: number): Promise<string> {
    at = NOW - daysAgo * DAY_MS;
    return store.emitInOwnTransaction(signedIn(realm));
  }

  async function adminEventAt(realm: string, daysAgo: number): Promise<string> {
    at = NOW - daysAgo * DAY_MS;
    return db().transaction((tx: DbTransaction) => store.emitAdminEvent(tx, change(realm)));
  }

  async function eventIds(realm: string, category?: EventCategory): Promise<string[]> {
    const { rows } = await pool().query<{ id: string }>(
      `SELECT id::text FROM events WHERE realm_id = $1 AND ($2::text IS NULL OR category = $2)
        ORDER BY events.seq`,
      [realm, category ?? null]
    );
    return rows.map((row) => row.id);
  }

  /**
   * What one job run does for one realm: every category, batch by batch,
   * until a batch is not full. Returns the rows deleted, or `busy`.
   */
  async function prune(
    realm: string,
    options: {
      policy?: EventRetentionPolicy;
      served?: OfferedDestinations;
      limit?: number;
      repo?: EventRetentionRepository;
    } = {}
  ): Promise<number | 'busy'> {
    const repo = options.repo ?? retention;
    const policy = options.policy ?? POLICY;
    const through = await repo.offeredThrough(realm, options.served);
    let deleted = 0;
    for (const [category, days] of [
      ['user', policy.userEventRetentionDays],
      ['admin', policy.adminEventRetentionDays],
    ] as const) {
      for (;;) {
        const batch = await repo.deleteBatch({
          realmId: realm,
          category,
          before: NOW - days * DAY_MS,
          through,
          limit: options.limit ?? 100,
          now: NOW,
        });
        if (batch.status === 'busy') return 'busy';
        deleted += batch.deleted;
        if (!batch.more) break;
      }
    }
    return deleted;
  }

  describe('the retention rule', () => {
    it('with 90 days set, deletes a user event 91 days old and keeps one 89 days old', async () => {
      const realm = randomUUID();
      await userEventAt(realm, 91);
      const young = await userEventAt(realm, 89);

      expect(await prune(realm)).toBe(1);
      expect(await eventIds(realm)).toEqual([young]);
    });

    it('deletes the oldest first, in batches', async () => {
      const realm = randomUUID();
      const byAge = new Map<number, string>();
      for (const days of [97, 100, 96, 99, 98]) byAge.set(days, await userEventAt(realm, days));
      const through = await retention.offeredThrough(realm);
      const batch = (limit: number) =>
        retention.deleteBatch({
          realmId: realm,
          category: 'user',
          before: NOW - 90 * DAY_MS,
          through,
          limit,
          now: NOW,
        });

      expect(await batch(2)).toEqual({
        status: 'done',
        deleted: 2,
        more: true,
        anchor: null,
        chainBreak: null,
      });
      expect(new Set(await eventIds(realm))).toEqual(
        new Set([byAge.get(98), byAge.get(97), byAge.get(96)])
      );
      expect(await batch(2)).toMatchObject({ deleted: 2, more: true });
      expect(await eventIds(realm)).toEqual([byAge.get(96)]);
      expect(await batch(2)).toMatchObject({ deleted: 1, more: false });
      expect(await eventIds(realm)).toEqual([]);
    });

    it('keeps admin events past the user retention until their own retention', async () => {
      const realm = randomUUID();
      await userEventAt(realm, 100);
      const recentAdmin = await adminEventAt(realm, 100);
      const head = await adminEventAt(realm, 1);

      expect(await prune(realm)).toBe(1);
      expect(await eventIds(realm)).toEqual([recentAdmin, head]);
    });

    it("reads each realm's retention, and the fallback for a realm whose row is gone", async () => {
      const {
        rows: [own],
      } = await pool().query<{ id: string }>(
        `INSERT INTO realms (name, user_event_retention_days, admin_event_retention_days)
         VALUES ('own', 30, 120) RETURNING id::text`
      );
      const gone = randomUUID();
      await userEventAt(own.id, 1);
      await userEventAt(gone, 1);

      const fallback = { userEventRetentionDays: 7, adminEventRetentionDays: 100 };
      expect(await retention.realms(fallback)).toEqual(
        expect.arrayContaining([
          {
            realmId: own.id,
            realmExists: true,
            userEventRetentionDays: 30,
            adminEventRetentionDays: 120,
          },
          { realmId: gone, realmExists: false, ...fallback },
        ])
      );
      expect(await retention.realms(fallback)).toHaveLength(2);
      await expect(
        retention.realms({ userEventRetentionDays: 7, adminEventRetentionDays: 89 })
      ).rejects.toThrow(TypeError);
    });

    it("reports the time of each category's oldest event, over every realm", async () => {
      expect(await retention.oldestEventTimes()).toEqual({ user: null, admin: null });
      const [a, b] = [randomUUID(), randomUUID()];
      await userEventAt(a, 10);
      await userEventAt(b, 20);
      await adminEventAt(b, 5);

      expect(await retention.oldestEventTimes()).toEqual({
        user: NOW - 20 * DAY_MS,
        admin: NOW - 5 * DAY_MS,
      });
    });
  });

  describe('the offered rule', () => {
    const webhooks = (realm: string, ...ids: string[]) =>
      ids.map((id) => ({ kind: 'webhook', id, realmId: realm }));

    /** Fan out, and claim and record the one due delivery of a destination. */
    async function attempt(
      destination: string,
      result: 'delivered' | 'retry' | 'failed',
      now: number
    ): Promise<void> {
      const [claim] = await queue.claim({
        picks: [{ kind: 'webhook', id: destination, limit: 1 }],
        now,
        leaseMs: LEASE,
        maxAttempts: 5,
      });
      expect(claim).toBeDefined();
      await queue.record(
        claim,
        result === 'delivered'
          ? { result }
          : result === 'retry'
            ? { result, errorClass: 'timeout', nextAttemptAt: now + 1 }
            : { result, errorClass: 'http_status', statusCode: 410 },
        now
      );
    }

    it.each(['delivered', 'failed'] as const)(
      'keeps an expired event with a pending webhook delivery until it is %s',
      async (outcome) => {
        const realm = randomUUID();
        const destinations = webhooks(realm, 'a');
        const served = { kinds: ['webhook'], destinations };
        await queue.fanOut({ kinds: ['webhook'], destinations, now: NOW });
        const old = await userEventAt(realm, 91);
        await queue.fanOut({ kinds: ['webhook'], destinations, now: NOW });

        expect(await prune(realm, { served })).toBe(0);
        await attempt('a', 'retry', NOW);
        expect(await prune(realm, { served })).toBe(0);
        expect(await eventIds(realm)).toEqual([old]);

        await attempt('a', outcome, NOW + 1);
        expect(await prune(realm, { served })).toBe(1);
        expect(await eventIds(realm)).toEqual([]);
        // The delivery history goes with the event, through the foreign key.
        expect(await queue.listForEvent(old)).toEqual([]);
      }
    );

    it('keeps an event the fan-out has not read yet', async () => {
      const realm = randomUUID();
      const destinations = webhooks(realm, 'a');
      await queue.fanOut({ kinds: ['webhook'], destinations, now: NOW });
      const old = await userEventAt(realm, 91);

      expect(await prune(realm, { served: { kinds: ['webhook'], destinations } })).toBe(0);
      expect(await eventIds(realm)).toEqual([old]);
    });

    it('lets no disabled destination of a listed route hold an event back', async () => {
      const realm = randomUUID();
      await queue.fanOut({ kinds: ['webhook'], destinations: webhooks(realm, 'a', 'b'), now: NOW });
      const old = await userEventAt(realm, 91);
      await queue.fanOut({ kinds: ['webhook'], destinations: webhooks(realm, 'a', 'b'), now: NOW });
      await attempt('a', 'delivered', NOW);

      // Without the route's listing, b's pending delivery counts.
      expect(await prune(realm)).toBe(0);
      // A route that lists only `a`: b is disabled.
      expect(
        await prune(realm, { served: { kinds: ['webhook'], destinations: webhooks(realm, 'a') } })
      ).toBe(1);
      expect(await eventIds(realm)).toEqual([]);
      expect(await queue.listForEvent(old)).toEqual([]);
    });

    it("lets no route kind without an enabled destination hold the realm's events back", async () => {
      const realm = randomUUID();
      await queue.fanOut({ kinds: ['webhook'], destinations: webhooks(realm, 'a'), now: NOW });
      await userEventAt(realm, 91);

      expect(await prune(realm)).toBe(0);
      expect(await prune(realm, { served: { kinds: ['webhook'], destinations: [] } })).toBe(1);
    });

    it('stops the admin chain at its oldest row not offered yet', async () => {
      const realm = randomUUID();
      const destinations = webhooks(realm, 'a');
      const served = { kinds: ['webhook'], destinations };
      await adminEventAt(realm, 400);
      await queue.fanOut({ kinds: ['webhook'], destinations, now: NOW });
      const second = await adminEventAt(realm, 399);
      const third = await adminEventAt(realm, 398);
      const head = await adminEventAt(realm, 1);
      await queue.fanOut({ kinds: ['webhook'], destinations, now: NOW });
      // The third is delivered; the second is still being retried.
      const claims = await queue.claim({
        picks: [{ kind: 'webhook', id: 'a', limit: 3 }],
        now: NOW,
        leaseMs: LEASE,
        maxAttempts: 5,
      });
      for (const claim of claims) {
        await queue.record(
          claim,
          claim.eventId === second
            ? { result: 'retry', errorClass: 'timeout', nextAttemptAt: NOW + 1 }
            : { result: 'delivered' },
          NOW
        );
      }

      expect(await prune(realm, { served })).toBe(1);
      // The first is deleted; the third, offered, waits behind the second.
      expect(await eventIds(realm)).toEqual([second, third, head]);
    });
  });

  describe('the admin chain', () => {
    it('verifies from the anchor after its oldest rows are deleted, and fails once the anchor is changed', async () => {
      const realm = randomUUID();
      const old = [
        await adminEventAt(realm, 400),
        await adminEventAt(realm, 390),
        await adminEventAt(realm, 380),
      ];
      const kept = [await adminEventAt(realm, 10), await adminEventAt(realm, 1)];
      const before = await store.verifyChain(realm);
      expect(before).toMatchObject({ ok: true, rowsChecked: 5 });
      const { rows: oldRows } = await pool().query<{ seq: string; hash: Buffer }>(
        'SELECT seq::text, hash FROM events WHERE id = ANY($1::uuid[]) ORDER BY events.seq',
        [old]
      );

      expect(await prune(realm)).toBe(3);
      expect(await eventIds(realm)).toEqual(kept);
      const anchor = { seq: BigInt(oldRows[2].seq), hash: oldRows[2].hash.toString('hex') };
      const { rows: stored } = await pool().query(
        'SELECT seq::text, encode(hash, $2) AS hash FROM event_chain_anchors WHERE realm_id = $1',
        [realm, 'hex']
      );
      expect(stored).toEqual([{ seq: oldRows[2].seq, hash: anchor.hash }]);

      // From the anchor, by default, and from any point retention has passed.
      const after = await store.verifyChain(realm);
      expect(after).toEqual({
        ok: true,
        realmId: realm,
        from: anchor,
        rowsChecked: 2,
        head: before.ok ? before.head : null,
      });
      const fromOldPoint = await store.verifyChain(realm, {
        seq: BigInt(oldRows[0].seq),
        hash: oldRows[0].hash.toString('hex'),
      });
      expect(fromOldPoint).toMatchObject({ ok: true, from: anchor, rowsChecked: 2 });
      expect(
        await store.verifyChain(realm, { seq: anchor.seq, hash: 'ab'.repeat(32) })
      ).toMatchObject({
        ok: false,
        break: { id: null, seq: anchor.seq, reason: 'anchor_mismatch' },
      });

      await pool().query(
        `UPDATE event_chain_anchors SET hash = decode(repeat('ab', 32), 'hex') WHERE realm_id = $1`,
        [realm]
      );
      expect(await store.verifyChain(realm)).toMatchObject({
        ok: false,
        rowsChecked: 0,
        break: { id: kept[0], reason: 'prev_hash_mismatch' },
      });
    });

    it('never deletes the head, so the next admin event still follows the chain', async () => {
      const realm = randomUUID();
      await adminEventAt(realm, 400);
      await adminEventAt(realm, 399);
      const head = await adminEventAt(realm, 398);

      expect(await prune(realm)).toBe(2);
      expect(await eventIds(realm)).toEqual([head]);
      // The old head is the start of the chain once a new admin event follows it.
      const next = await adminEventAt(realm, 0);
      expect(await prune(realm)).toBe(1);
      expect(await eventIds(realm)).toEqual([next]);
      expect(await store.verifyChain(realm)).toMatchObject({
        ok: true,
        rowsChecked: 1,
        head: { id: next },
      });
    });

    it('stops at a row that breaks the chain, and leaves it for verifyChain to report', async () => {
      const realm = randomUUID();
      const first = await adminEventAt(realm, 400);
      const changed = await adminEventAt(realm, 399);
      await adminEventAt(realm, 398);
      await adminEventAt(realm, 1);
      const client: PoolClient = await pool().connect();
      try {
        await client.query('BEGIN');
        await client.query('SET LOCAL session_replication_role = replica');
        await client.query(
          `UPDATE events SET data = jsonb_set(data, '{operation}', '"realms.keys.write"') WHERE id = $1`,
          [changed]
        );
        await client.query('COMMIT');
      } finally {
        client.release();
      }

      const through = await retention.offeredThrough(realm);
      const batch = await retention.deleteBatch({
        realmId: realm,
        category: 'admin',
        before: NOW - 365 * DAY_MS,
        through,
        limit: 100,
        now: NOW,
      });
      expect(batch).toMatchObject({
        status: 'done',
        deleted: 1,
        more: false,
        chainBreak: { id: changed, reason: 'hash_mismatch' },
      });
      expect(await eventIds(realm)).not.toContain(first);
      expect(await store.verifyChain(realm)).toMatchObject({
        ok: false,
        break: { id: changed, reason: 'hash_mismatch' },
      });
      expect(await prune(realm)).toBe(0);
    });

    it('deletes admin rows written before the chain by their time', async () => {
      const realm = randomUUID();
      // A suspension migration 0031 copied from audit_logs: an admin row
      // without a hash, which events_admin_chained (NOT VALID) let stay.
      const client: PoolClient = await pool().connect();
      try {
        await client.query('BEGIN');
        await client.query('ALTER TABLE events DROP CONSTRAINT events_admin_chained');
        await client.query(
          `INSERT INTO events (id, realm_id, category, type, time, data, schema_version)
           VALUES (uuidv7(), $1, 'admin', 'urn:qauth:event:client.suspended:v1-rc.0', $2, '{}', 1)`,
          [realm, NOW - 400 * DAY_MS]
        );
        await client.query(
          `ALTER TABLE events ADD CONSTRAINT events_admin_chained
             CHECK ((category = 'admin') = (hash IS NOT NULL)) NOT VALID`
        );
        await client.query('COMMIT');
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
      const head = await adminEventAt(realm, 1);

      expect(await prune(realm)).toBe(1);
      expect(await eventIds(realm)).toEqual([head]);
    });
  });

  describe('two job instances at once', () => {
    it('delete each row once and raise no error', async () => {
      if (!ctx) throw new Error('no ctx');
      const realms = [randomUUID(), randomUUID()];
      const expected: string[] = [];
      const kept: string[] = [];
      for (const realm of realms) {
        for (let i = 0; i < 12; i += 1) expected.push(await userEventAt(realm, 200 - i));
        for (let i = 0; i < 6; i += 1) expected.push(await adminEventAt(realm, 400 - i));
        kept.push(await adminEventAt(realm, 1));
      }
      const pools = [0, 1].map(() => new Pool({ connectionString: ctx?.connectionString, max: 2 }));
      try {
        const repos = pools.map((p) =>
          createEventRetentionRepository(drizzle(p) as unknown as Database)
        );
        // Each instance runs every realm, batch by batch, and tries a batch
        // again when the other holds the realm, as the next run would.
        const run = async (repo: EventRetentionRepository): Promise<number> => {
          let deleted = 0;
          for (const realm of realms) {
            const through = await repo.offeredThrough(realm);
            for (const [category, days] of [
              ['user', 90],
              ['admin', 365],
            ] as const) {
              for (;;) {
                const batch = await repo.deleteBatch({
                  realmId: realm,
                  category,
                  before: NOW - days * DAY_MS,
                  through,
                  limit: 2,
                  now: NOW,
                });
                if (batch.status === 'busy') continue;
                deleted += batch.deleted;
                if (!batch.more) break;
              }
            }
          }
          return deleted;
        };
        const counts = await Promise.all(repos.map(run));

        expect(counts[0] + counts[1]).toBe(expected.length);
        const { rows } = await pool().query<{ id: string }>('SELECT id::text FROM events');
        expect(rows.map((row) => row.id).sort()).toEqual([...kept].sort());
        for (const realm of realms) {
          expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 1 });
        }
      } finally {
        await Promise.all(pools.map((p) => p.end()));
      }
    });
  });

  describe('database roles', () => {
    const roles = {
      retention: 'qauth_event_retention',
      writer: 'qauth_event_writer_536',
      delivery: 'qauth_event_delivery_536',
    } as const;
    const pools: Partial<Record<keyof typeof roles, Pool>> = {};

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      const statements = {
        retention: eventRetentionGrantStatements,
        writer: eventsWriterGrantStatements,
        delivery: eventDeliveryGrantStatements,
      };
      for (const [key, role] of Object.entries(roles) as [keyof typeof roles, string][]) {
        await pool().query(`CREATE ROLE ${role} LOGIN PASSWORD '${role}'`);
        await pool().query(`GRANT USAGE ON SCHEMA public TO ${role}`);
        for (const statement of statements[key](role)) await pool().query(statement);
        const url = new URL(ctx.connectionString);
        url.username = role;
        url.password = role;
        pools[key] = new Pool({ connectionString: url.toString(), max: 2 });
      }
    });

    afterAll(async () => {
      await Promise.all(Object.values(pools).map((p) => p?.end()));
    });

    function as(key: keyof typeof roles): Pool {
      const found = pools[key];
      if (!found) throw new Error(`no pool for ${key}`);
      return found;
    }

    it('lets a role without the retention grant delete nothing from events', async () => {
      const realm = randomUUID();
      await userEventAt(realm, 100);
      for (const key of ['writer', 'delivery'] as const) {
        expect(await sqlState(as(key).query('DELETE FROM events')), key).toBe('42501');
        expect(await sqlState(as(key).query('DELETE FROM event_chain_anchors')), key).toBe('42501');
      }
      expect(await eventIds(realm)).toHaveLength(1);
    });

    it('lets the retention role do the whole job, deliveries and anchor included', async () => {
      const repo = createEventRetentionRepository(drizzle(as('retention')) as unknown as Database);
      const realm = randomUUID();
      await pool().query(`INSERT INTO realms (id, name) VALUES ($1, 'retained')`, [realm]);
      const destinations = [{ kind: 'webhook', id: 'a', realmId: realm }];
      await queue.fanOut({ kinds: ['webhook'], destinations, now: NOW });
      await userEventAt(realm, 100);
      await adminEventAt(realm, 400);
      await adminEventAt(realm, 399);
      const head = await adminEventAt(realm, 1);
      await queue.fanOut({ kinds: ['webhook'], destinations, now: NOW });
      // One delivery per event: the user event and the three admin events.
      for (let delivered = 0; delivered < 4; delivered += 1) {
        const [claim] = await queue.claim({
          picks: [{ kind: 'webhook', id: 'a', limit: 1 }],
          now: NOW,
          leaseMs: LEASE,
          maxAttempts: 5,
        });
        await queue.record(claim, { result: 'delivered' }, NOW);
      }

      expect(await repo.realms(POLICY)).toEqual([{ realmId: realm, realmExists: true, ...POLICY }]);
      expect(await prune(realm, { repo, served: { kinds: ['webhook'], destinations } })).toBe(3);
      expect(await eventIds(realm)).toEqual([head]);
      expect(await repo.oldestEventTimes()).toEqual({ user: null, admin: NOW - DAY_MS });
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 1 });

      for (const statement of [
        `INSERT INTO events (id, realm_id, category, type, time, data, schema_version)
           VALUES (uuidv7(), '${realm}', 'user', 'x', 0, '{}', 1)`,
        `DELETE FROM event_deliveries`,
        `DELETE FROM event_chain_anchors`,
        `UPDATE realms SET admin_event_retention_days = 90`,
        `SELECT issuer FROM realms`,
        `SELECT * FROM users`,
        `SELECT * FROM realm_keys`,
      ]) {
        expect(await sqlState(as('retention').query(statement)), statement).toBe('42501');
      }
    });
  });
});
