/**
 * Real-Postgres integration tests for the event store (issue #457).
 *
 * What only a database can prove: an event commits and rolls back with the
 * change it records; a reader that polls while transactions commit out of
 * `xid` order never skips or repeats an event; an open transaction holds
 * back the events committed after it began, until it ends; a read of one
 * realm never returns another's; a role granted only `INSERT` can write
 * while it can read nothing back; and the telemetry sink is handed an event
 * only once the COMMIT has succeeded (issue #541).
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { randomUUID } from 'node:crypto';

import { parseEvent } from '@qauth-labs/shared-events';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Database, DbTransaction, EmitEvent, EventsRepository } from '../../types';
import {
  decodeEventPosition,
  type EventPosition,
  EventPositionError,
  eventStreamStart,
} from '../events/position';
import { createEventsRepository } from './events.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository } from './realms.repository';

const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
const SIGNED_OUT = 'urn:qauth:event:user.signed_out:v1-rc.0';

/** A sign-in event of one user in one realm. */
function signedIn(
  realm: string,
  userId: string = randomUUID()
): EmitEvent<'urn:qauth:event:user.signed_in:v1-rc.0'> {
  return {
    type: SIGNED_IN,
    realm,
    actor: { type: 'user', id: userId },
    subject: { type: 'user', id: userId },
    data: { method: 'password' },
  };
}

/** A promise with its resolve function, to order steps across transactions. */
function gate(): { promise: Promise<void>; open: () => void } {
  let open: () => void = () => undefined;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}

/** Thrown inside a transaction to roll it back on purpose. */
class Rollback extends Error {}

describe('events integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let store: EventsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    // A container of its own: a case below creates roles, which are
    // cluster-wide and outlive the database, so on a shared server their
    // fixed names would meet the next suite's.
    ctx = await setupIntegrationDb({ privateContainer: true });
    store = createEventsRepository(ctx.database.db);
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

  function db(): Database {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.db;
  }

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  async function countById(id: string): Promise<number> {
    const { rows } = await pool().query('SELECT count(*)::int AS n FROM events WHERE id = $1', [
      id,
    ]);
    return rows[0].n;
  }

  /** Every id a realm's stream holds, in (xid, seq) order, read directly. */
  async function idsInStreamOrder(realm: string): Promise<string[]> {
    const { rows } = await pool().query(
      'SELECT id FROM events WHERE realm_id = $1 ORDER BY xid, seq',
      [realm]
    );
    return rows.map((row: { id: string }) => row.id);
  }

  /** Read a realm from `position` until a page comes back empty. */
  async function drain(
    realm: string,
    position: EventPosition,
    limit = 100
  ): Promise<{ ids: string[]; next: EventPosition }> {
    const ids: string[] = [];
    let next = position;
    // Bounded, so a reader that never reaches the end fails instead of hanging.
    for (let pages = 0; pages < 1000; pages += 1) {
      const page = await store.readAfter(realm, next, limit);
      ids.push(...page.events.map((stored) => stored.event.id));
      next = page.next;
      if (page.events.length === 0) return { ids, next };
    }
    throw new Error(`reading realm ${realm} did not reach the end in 1000 pages`);
  }

  describe('the write rule', () => {
    it('an event emitted in a rolled-back transaction does not exist; one in a committed transaction exists once', async () => {
      const realm = randomUUID();
      const realms = createRealmsRepository(db());
      const realmName = `rolled-back-${randomUUID()}`;
      let rolledBack = '';

      await expect(
        db().transaction(async (tx) => {
          await realms.create({ name: realmName }, tx);
          rolledBack = await store.emit(tx, signedIn(realm));
          throw new Rollback();
        })
      ).rejects.toBeInstanceOf(Rollback);

      const committed = await db().transaction(async (tx) => {
        await realms.create({ name: `committed-${randomUUID()}` }, tx);
        return store.emit(tx, signedIn(realm));
      });

      expect(rolledBack).not.toBe('');
      expect(await countById(rolledBack)).toBe(0);
      // The change rolled back with its event.
      expect(await realms.findByName(realmName)).toBeUndefined();
      expect(await countById(committed)).toBe(1);
      expect((await drain(realm, eventStreamStart(realm))).ids).toEqual([committed]);
    });

    it('a caller without a transaction gets a short one of its own', async () => {
      const realm = randomUUID();
      const id = await store.emitInOwnTransaction(signedIn(realm));
      expect(await countById(id)).toBe(1);
    });

    it('reads back the envelope it wrote, which still passes the contract', async () => {
      const at = Date.UTC(2026, 9, 23, 9, 30, 0, 250);
      const clocked = createEventsRepository(db(), { now: () => at });
      const realm = randomUUID();
      const userId = randomUUID();
      const emitted = {
        type: SIGNED_IN,
        realm,
        actor: { type: 'client', id: 'agent-1', delegationChain: ['agent-1', 'portal'] },
        subject: { type: 'user', id: userId },
        client: { id: 'agent-1' },
        request: { traceId: 'req-42', ip: '2001:db8::1', userAgent: 'agent/1.0' },
        data: { method: 'password', verifierProfile: 'oid4vp-1.0-base' },
      } as const satisfies EmitEvent<typeof SIGNED_IN>;

      const id = await db().transaction((tx) => clocked.emit(tx, emitted));
      const page = await store.readAfter(realm, eventStreamStart(realm), 10);

      expect(page.events).toHaveLength(1);
      const [{ event }] = page.events;
      expect(event).toEqual({
        id,
        time: new Date(at).toISOString(),
        category: 'user',
        ...emitted,
      });
      expect(parseEvent(event)).toEqual(event);
    });
  });

  describe('the telemetry rule (issue #541)', () => {
    /** A repository whose sink keeps the ids it is handed. */
    function withSink(): { repo: EventsRepository; handed: string[] } {
      const handed: string[] = [];
      const repo = createEventsRepository(db(), {
        telemetry: { record: (e) => handed.push(e.id) },
      });
      return { repo, handed };
    }

    it('hands over a committed event once, after the COMMIT, and never one that rolled back', async () => {
      const { repo, handed } = withSink();
      const realm = randomUUID();
      let rolledBack = '';

      const committed = await db().transaction(async (tx) => {
        const id = await repo.emit(tx, signedIn(realm));
        expect(handed).toEqual([]);
        return id;
      });
      await expect(
        db().transaction(async (tx) => {
          rolledBack = await repo.emit(tx, signedIn(realm));
          throw new Rollback();
        })
      ).rejects.toBeInstanceOf(Rollback);

      expect(handed).toEqual([committed]);
      expect(await countById(committed)).toBe(1);
      expect(await countById(rolledBack)).toBe(0);
    });

    it("keeps a released savepoint's event for the outer COMMIT and drops a rolled-back savepoint's", async () => {
      const { repo, handed } = withSink();
      const realm = randomUUID();
      let kept = '';
      let dropped = '';

      await db().transaction(async (tx) => {
        kept = await tx.transaction((savepoint) => repo.emit(savepoint, signedIn(realm)));
        await expect(
          tx.transaction(async (savepoint) => {
            dropped = await repo.emit(savepoint, signedIn(realm));
            throw new Rollback();
          })
        ).rejects.toBeInstanceOf(Rollback);
        expect(handed).toEqual([]);
      });

      expect(handed).toEqual([kept]);
      expect(await countById(kept)).toBe(1);
      expect(await countById(dropped)).toBe(0);
    });

    it('drops the event when the COMMIT itself fails', async () => {
      const { repo, handed } = withSink();
      const realm = randomUUID();
      // A deferred unique constraint is checked at COMMIT, so the statements
      // succeed and the COMMIT fails.
      await pool().query(
        'CREATE TABLE telemetry_commit_probe (x int, CONSTRAINT telemetry_commit_probe_x UNIQUE (x) DEFERRABLE INITIALLY DEFERRED)'
      );
      try {
        let id = '';
        await expect(
          db().transaction(async (tx) => {
            id = await repo.emit(tx, signedIn(realm));
            await tx.execute(sql`INSERT INTO telemetry_commit_probe (x) VALUES (1), (1)`);
          })
        ).rejects.toMatchObject({ cause: { code: '23505' } });
        expect(await countById(id)).toBe(0);
        expect(handed).toEqual([]);
      } finally {
        await pool().query('DROP TABLE telemetry_commit_probe');
      }
    });

    it('drops the event of a transaction a caught statement error aborted, whose COMMIT Postgres answers with ROLLBACK', async () => {
      const { repo, handed } = withSink();
      let id = '';

      await db().transaction(async (tx) => {
        id = await repo.emit(tx, signedIn(randomUUID()));
        await tx.execute(sql`SELECT 1 / 0`).catch(() => undefined);
      });

      expect(await countById(id)).toBe(0);
      expect(handed).toEqual([]);
    });

    it('hands over an event written in its own transaction once it is stored', async () => {
      const { repo, handed } = withSink();
      const id = await repo.emitInOwnTransaction(signedIn(randomUUID()));
      expect(handed).toEqual([id]);
      expect(await countById(id)).toBe(1);
    });
  });

  describe('the read rule', () => {
    it('a reader polling for 200 rounds, while transactions commit in the reverse order of their xid, never skips and never repeats an event', async () => {
      const realm = randomUUID();
      const committed: string[] = [];
      const rolledBack: string[] = [];
      let stop = false;

      // Each round, the older transaction (it writes first, so its xid is
      // lower) commits after the younger one. A reader ordered by seq or by
      // commit time would pass the younger one's rows and skip the older's.
      async function writer(): Promise<number> {
        let reversals = 0;
        while (!stop) {
          const olderWrote = gate();
          const youngerCommitted = gate();
          const olderIds: string[] = [];
          const older = db().transaction(async (tx) => {
            olderIds.push(await store.emit(tx, signedIn(realm)));
            olderWrote.open();
            await youngerCommitted.promise;
            olderIds.push(await store.emit(tx, signedIn(realm)));
          });
          await olderWrote.promise;
          const younger = await db().transaction(async (tx) => [
            await store.emit(tx, signedIn(realm)),
            await store.emit(tx, signedIn(realm)),
          ]);
          committed.push(...younger);
          youngerCommitted.open();
          await older;
          committed.push(...olderIds);
          reversals += 1;

          await db()
            .transaction(async (tx) => {
              rolledBack.push(await store.emit(tx, signedIn(realm)));
              throw new Rollback();
            })
            .catch((error: unknown) => {
              if (!(error instanceof Rollback)) throw error;
            });
        }
        return reversals;
      }

      async function reader(): Promise<{ ids: string[]; next: EventPosition }> {
        const ids: string[] = [];
        let next = eventStreamStart(realm);
        for (let round = 0; round < 200; round += 1) {
          const page = await store.readAfter(realm, next, 3);
          ids.push(...page.events.map((stored) => stored.event.id));
          next = page.next;
          await new Promise((resolve) => setImmediate(resolve));
        }
        stop = true;
        return { ids, next };
      }

      const [polled, reversalsA, reversalsB] = await Promise.all([reader(), writer(), writer()]);
      // Every transaction has ended: one more pass takes what is left.
      const rest = await drain(realm, polled.next, 3);
      const seen = [...polled.ids, ...rest.ids];

      expect(reversalsA + reversalsB).toBeGreaterThan(0);
      expect(polled.ids.length).toBeGreaterThan(0);
      expect(new Set(seen).size).toBe(seen.length);
      expect([...seen].sort()).toEqual([...committed].sort());
      expect(seen).toEqual(await idsInStreamOrder(realm));
      for (const id of rolledBack) expect(seen).not.toContain(id);
    });

    it('while a transaction is open, the events committed after it began are not returned; they appear when it ends', async () => {
      const realm = randomUUID();
      let clock = Date.now();
      const clocked = createEventsRepository(db(), { now: () => clock });

      const before = await clocked.emitInOwnTransaction(signedIn(realm));

      const started = gate();
      const release = gate();
      const open = db().transaction(async (tx) => {
        // A transaction holds readers back once it has a transaction id,
        // which its first write, or this call, gives it.
        await tx.execute(sql`select pg_current_xact_id()`);
        started.open();
        await release.promise;
      });
      await started.promise;

      let afterOwn: string;
      let afterTx: string;
      let held: { ids: string[]; next: EventPosition };
      try {
        afterOwn = await clocked.emitInOwnTransaction(signedIn(realm));
        afterTx = await db().transaction((tx) => clocked.emit(tx, signedIn(realm)));
        expect(await countById(afterOwn)).toBe(1);
        expect(await countById(afterTx)).toBe(1);

        // One page, not a drain: a reader that ignored the horizon could loop.
        const page = await store.readAfter(realm, eventStreamStart(realm), 100);
        held = { ids: page.events.map((stored) => stored.event.id), next: page.next };
        expect(held.ids).toEqual([before]);

        clock += 5_000;
        expect(await clocked.oldestUnreadEventAge()).toBeGreaterThanOrEqual(5);
      } finally {
        release.open();
        await open;
      }

      const after = await drain(realm, held.next);
      expect(after.ids).toEqual([afterOwn, afterTx]);
      expect(await clocked.oldestUnreadEventAge()).toBe(0);
    });

    it('a read of another realm returns nothing, and a position of another realm is refused', async () => {
      const realmA = randomUUID();
      const realmB = randomUUID();
      const id = await store.emitInOwnTransaction(signedIn(realmA));

      const ofB = await store.readAfter(realmB, eventStreamStart(realmB), 100);
      expect(ofB.events).toEqual([]);
      expect(decodeEventPosition(ofB.next).realmId).toBe(realmB);

      const ofA = await store.readAfter(realmA, eventStreamStart(realmA), 100);
      expect(ofA.events.map((stored) => stored.event.id)).toEqual([id]);

      await expect(store.readAfter(realmB, ofA.next, 100)).rejects.toBeInstanceOf(
        EventPositionError
      );
    });

    it('applies the filters in the database, and a position read with one filter continues with another', async () => {
      const realm = randomUUID();
      const alice = randomUUID();
      const bob = randomUUID();
      const aliceIn = await store.emitInOwnTransaction(signedIn(realm, alice));
      const bobIn = await store.emitInOwnTransaction(signedIn(realm, bob));
      const aliceOut = await store.emitInOwnTransaction({
        type: SIGNED_OUT,
        realm,
        actor: { type: 'user', id: alice },
        subject: { type: 'user', id: alice },
        client: { id: 'portal' },
        data: {},
      });

      const read = (filters: Parameters<EventsRepository['readAfter']>[3]) =>
        store
          .readAfter(realm, eventStreamStart(realm), 100, filters)
          .then((page) => page.events.map((stored) => stored.event.id));

      expect(await read({ types: [SIGNED_OUT] })).toEqual([aliceOut]);
      expect(await read({ types: [] })).toEqual([]);
      expect(await read({ subjectId: alice })).toEqual([aliceIn, aliceOut]);
      expect(await read({ clientId: 'portal' })).toEqual([aliceOut]);
      expect(await read({ category: 'admin' })).toEqual([]);
      expect(await read({ fromTime: Date.now() + 60_000 })).toEqual([]);

      const first = await store.readAfter(realm, eventStreamStart(realm), 1, { subjectId: bob });
      expect(first.events.map((stored) => stored.event.id)).toEqual([bobIn]);
      const rest = await store.readAfter(realm, first.next, 100);
      expect(rest.events.map((stored) => stored.event.id)).toEqual([aliceOut]);
    });
  });

  describe('a role granted only INSERT on events', () => {
    const WRITER = 'qauth_events_writer';
    const READER = 'qauth_events_reader';
    let writerPool: Pool | undefined;
    let readerPool: Pool | undefined;

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      // Login roles are cluster-wide and outlive `reset()`; the container is
      // per file, so creating them once here is enough. The per-role grants
      // themselves belong to the topology area; these stand in for them.
      for (const [role, privilege] of [
        [WRITER, 'INSERT'],
        [READER, 'SELECT'],
      ] as const) {
        await pool().query(`CREATE ROLE ${role} LOGIN PASSWORD '${role}'`);
        await pool().query(`GRANT USAGE ON SCHEMA public TO ${role}`);
        await pool().query(`GRANT ${privilege} ON TABLE events TO ${role}`);
      }
      const as = (role: string) => {
        if (!ctx) throw new Error('no ctx');
        const url = new URL(ctx.connectionString);
        url.username = role;
        url.password = role;
        return new Pool({ connectionString: url.toString(), max: 2 });
      };
      writerPool = as(WRITER);
      readerPool = as(READER);
    });

    afterAll(async () => {
      await writerPool?.end();
      await readerPool?.end();
    });

    function writerDb(): Database {
      if (!writerPool) throw new Error('no writer pool');
      return drizzle(writerPool) as unknown as Database;
    }

    function readerDb(): Database {
      if (!readerPool) throw new Error('no reader pool');
      return drizzle(readerPool) as unknown as Database;
    }

    /** The SQLSTATE behind a rejected promise. */
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

    it('can emit in a transaction and in one of its own, without a grant on the identity sequence', async () => {
      const realm = randomUUID();
      const writer = createEventsRepository(writerDb());

      const inTx = await writerDb().transaction((tx: DbTransaction) =>
        writer.emit(tx, signedIn(realm))
      );
      const own = await writer.emitInOwnTransaction(signedIn(realm));

      expect((await drain(realm, eventStreamStart(realm))).ids).toEqual([inTx, own]);
    });

    it('cannot read, change or remove an event', async () => {
      const realm = randomUUID();
      await store.emitInOwnTransaction(signedIn(realm));
      const writer = createEventsRepository(writerDb());

      // 42501 = insufficient_privilege.
      expect(await sqlState(writer.readAfter(realm, eventStreamStart(realm), 10))).toBe('42501');
      for (const statement of [
        'SELECT id FROM events',
        `UPDATE events SET data = '{}'`,
        'DELETE FROM events',
        'TRUNCATE events',
      ]) {
        expect(await sqlState(writerPool?.query(statement) ?? Promise.resolve())).toBe('42501');
      }
    });

    it('a role granted only SELECT can read but not emit', async () => {
      const realm = randomUUID();
      const id = await store.emitInOwnTransaction(signedIn(realm));
      const reader = createEventsRepository(readerDb());

      const page = await reader.readAfter(realm, eventStreamStart(realm), 10);
      expect(page.events.map((stored) => stored.event.id)).toEqual([id]);
      expect(await sqlState(reader.emitInOwnTransaction(signedIn(realm)))).toBe('42501');
    });
  });
});
