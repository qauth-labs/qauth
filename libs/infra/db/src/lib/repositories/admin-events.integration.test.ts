/**
 * Real-Postgres integration tests for admin events and their hash chain
 * (issue #459).
 *
 * What only a database can prove: concurrent admin events of one realm form
 * one unbroken chain; a row a superuser changed or removed breaks it where
 * `verifyChain` says; a writer that raced the lock cannot fork it; the
 * trigger refuses every UPDATE, the owner's included; and a role holding the
 * writer grants can write and verify admin events but cannot change or remove
 * one.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { createHash, randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool, type PoolClient } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { AdminEventInput, Database, DbTransaction, EventsRepository } from '../../types';
import { canonicalizeJson } from '../admin-audit/canonical-json';
import { EVENT_CHAIN_GENESIS_HASH, operatorCliActor } from '../events/chain';
import { eventsWriterGrantStatements } from '../events/grants';
import { eventStreamStart } from '../events/position';
import { createEventsRepository } from './events.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';

const ADMIN_ID = '0192f1c4-4444-7000-8000-000000000004';
const GENESIS_HEX = EVENT_CHAIN_GENESIS_HASH.toString('hex');

/** One admin change to a realm's mail settings. */
function change(realm: string, overrides: Partial<AdminEventInput> = {}): AdminEventInput {
  return {
    realm,
    actor: { type: 'user', id: ADMIN_ID },
    operation: 'realms.mail.write',
    target: { type: 'realm', id: realm },
    before: { fromName: 'QAuth', smtp: { host: 'a.example', password: 'old-password' } },
    after: { fromName: `Ops ${randomUUID()}`, smtp: { host: 'a.example', password: 'new-pw' } },
    ...overrides,
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

/** The SQLSTATE behind a rejected promise, through drizzle's wrapping. */
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

interface ChainRowSql {
  id: string;
  seq: string;
  prev_hash: Buffer;
  hash: Buffer;
}

describe('admin events integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let store: EventsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    store = createEventsRepository(ctx.database.db, { verifyBatchSize: 7 });
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

  async function emitInTx(input: AdminEventInput, repo = store, on = db()): Promise<string> {
    return on.transaction((tx: DbTransaction) => repo.emitAdminEvent(tx, input));
  }

  /** A realm's admin rows, in chain order. */
  async function chainRows(realm: string): Promise<ChainRowSql[]> {
    const { rows } = await pool().query<ChainRowSql>(
      // Ordered by the column, not by the text alias of the same name.
      `SELECT id, seq::text AS seq, prev_hash, hash FROM events
        WHERE realm_id = $1 AND hash IS NOT NULL ORDER BY events.seq`,
      [realm]
    );
    return rows;
  }

  /**
   * Run statements as the superuser with every trigger off, the way an
   * attacker with superuser access, or an operator editing by hand, would.
   */
  async function tamper(statements: [string, unknown[]][]): Promise<void> {
    const client: PoolClient = await pool().connect();
    try {
      await client.query('BEGIN');
      await client.query('SET LOCAL session_replication_role = replica');
      for (const [text, values] of statements) await client.query(text, values);
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  describe('the chain', () => {
    // The acceptance criterion of #459: 50 concurrent admin events in one
    // realm produce one unbroken chain, and verifyChain passes.
    it('gives 50 concurrent admin events of one realm one unbroken chain, beside another realm', async () => {
      if (!ctx) throw new Error('no ctx');
      const realm = randomUUID();
      const other = randomUUID();
      // A pool of its own, one connection per transaction, so all 60 are open
      // at once and queue on the chain lock rather than on the pool.
      const wide = new Pool({
        connectionString: ctx.connectionString,
        max: 60,
        connectionTimeoutMillis: 30_000,
      });
      let ids: string[];
      try {
        const on = drizzle(wide) as unknown as Database;
        ids = await Promise.all(
          Array.from({ length: 60 }, (_, i) =>
            emitInTx(change(i % 6 === 5 ? other : realm), store, on)
          )
        );
      } finally {
        await wide.end();
      }
      expect(new Set(ids).size).toBe(60);

      // Each row, in seq order, follows the one before it.
      const rows = await chainRows(realm);
      const hex = (hash: Buffer) => hash.toString('hex');
      expect(rows).toHaveLength(50);
      expect(hex(rows[0].prev_hash)).toBe(GENESIS_HEX);
      expect(rows.slice(1).map((row) => hex(row.prev_hash))).toEqual(
        rows.slice(0, -1).map((row) => hex(row.hash))
      );
      expect(new Set(rows.map((row) => hex(row.hash))).size).toBe(50);

      const report = await store.verifyChain(realm);
      expect(report).toEqual({
        ok: true,
        realmId: realm,
        from: { seq: 0n, hash: GENESIS_HEX },
        rowsChecked: 50,
        head: {
          id: rows[49].id,
          seq: BigInt(rows[49].seq),
          hash: rows[49].hash.toString('hex'),
        },
      });
      expect(await store.verifyChain(other)).toMatchObject({ ok: true, rowsChecked: 10 });
    });

    it('hashes each row over prev_hash and the canonical JSON of the envelope a reader gets back', async () => {
      const realm = randomUUID();
      await emitInTx(change(realm));
      const [row] = await chainRows(realm);
      const page = await store.readAfter(realm, eventStreamStart(realm), 10);

      const expected = createHash('sha256')
        .update(row.prev_hash)
        .update(canonicalizeJson(page.events[0].event), 'utf8')
        .digest();
      expect(row.hash.toString('hex')).toBe(expected.toString('hex'));
    });

    it('leaves user events out of the chain, and chains every admin type emit writes', async () => {
      const realm = randomUUID();
      await store.emitInOwnTransaction({
        type: 'urn:qauth:event:user.signed_in:v1-rc.0',
        realm,
        actor: { type: 'user', id: ADMIN_ID },
        subject: { type: 'user', id: ADMIN_ID },
        data: { method: 'password' },
      });
      await store.emitInOwnTransaction({
        type: 'urn:qauth:event:client.suspended:v1-rc.0',
        realm,
        actor: operatorCliActor(),
        subject: { type: 'client', id: 'portal' },
        data: {},
      });
      await emitInTx(change(realm));

      const { rows } = await pool().query(
        `SELECT category, hash IS NOT NULL AS chained FROM events WHERE realm_id = $1 ORDER BY seq`,
        [realm]
      );
      expect(rows).toEqual([
        { category: 'user', chained: false },
        { category: 'admin', chained: true },
        { category: 'admin', chained: true },
      ]);
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 2 });
    });

    it('rolls an admin event back with its transaction, and the chain goes on from the head', async () => {
      const realm = randomUUID();
      await emitInTx(change(realm));
      await expect(
        db().transaction(async (tx: DbTransaction) => {
          await store.emitAdminEvent(tx, change(realm));
          throw new Rollback();
        })
      ).rejects.toBeInstanceOf(Rollback);
      await emitInTx(change(realm));

      expect(await chainRows(realm)).toHaveLength(2);
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 2 });
    });

    it('verifies from a point: the head an earlier run returned, or a hash that is wrong', async () => {
      const realm = randomUUID();
      for (let i = 0; i < 3; i += 1) await emitInTx(change(realm));
      const first = await store.verifyChain(realm);
      if (!first.ok || !first.head) throw new Error('expected a head');
      for (let i = 0; i < 2; i += 1) await emitInTx(change(realm));

      const later = await store.verifyChain(realm, first.head);
      expect(later).toMatchObject({
        ok: true,
        rowsChecked: 2,
        from: { seq: first.head.seq, hash: first.head.hash },
      });

      const wrong = await store.verifyChain(realm, { seq: first.head.seq, hash: 'ab'.repeat(32) });
      const rows = await chainRows(realm);
      expect(wrong).toMatchObject({
        ok: false,
        rowsChecked: 0,
        break: { id: rows[2].id, seq: first.head.seq, reason: 'anchor_mismatch' },
      });
    });

    it('passes on a realm with no admin event', async () => {
      expect(await store.verifyChain(randomUUID())).toMatchObject({
        ok: true,
        rowsChecked: 0,
        head: null,
      });
    });
  });

  describe('verifyChain finds what was changed behind the store', () => {
    async function fiveRows(realm: string): Promise<ChainRowSql[]> {
      for (let i = 0; i < 5; i += 1) await emitInTx(change(realm));
      return chainRows(realm);
    }

    // The acceptance criterion of #459: editing a stored admin row makes
    // verifyChain fail at that row.
    it('fails at the row a superuser edited', async () => {
      const realm = randomUUID();
      const rows = await fiveRows(realm);
      await tamper([
        [
          `UPDATE events SET data = jsonb_set(data, '{operation}', '"realms.delete"') WHERE id = $1`,
          [rows[2].id],
        ],
      ]);

      expect(await store.verifyChain(realm)).toEqual({
        ok: false,
        realmId: realm,
        from: { seq: 0n, hash: GENESIS_HEX },
        rowsChecked: 2,
        break: { id: rows[2].id, seq: BigInt(rows[2].seq), reason: 'hash_mismatch' },
      });
    });

    it('fails at the next row when the edited row was given a correct new hash', async () => {
      const realm = randomUUID();
      const rows = await fiveRows(realm);
      await tamper([[`UPDATE events SET actor_id = 'someone-else' WHERE id = $1`, [rows[1].id]]]);
      const page = await store.readAfter(realm, eventStreamStart(realm), 10);
      const edited = page.events.find((stored) => stored.event.id === rows[1].id);
      if (!edited) throw new Error('edited row not read');
      const rehash = createHash('sha256')
        .update(rows[1].prev_hash)
        .update(canonicalizeJson(edited.event), 'utf8')
        .digest();
      await tamper([[`UPDATE events SET hash = $2 WHERE id = $1`, [rows[1].id, rehash]]]);

      expect(await store.verifyChain(realm)).toMatchObject({
        ok: false,
        rowsChecked: 2,
        break: { id: rows[2].id, reason: 'prev_hash_mismatch' },
      });
    });

    // The acceptance criterion of #459: deleting a middle row makes
    // verifyChain fail at the next row.
    it('fails at the row after one deleted from the middle', async () => {
      const realm = randomUUID();
      const rows = await fiveRows(realm);
      await pool().query('DELETE FROM events WHERE id = $1', [rows[2].id]);

      expect(await store.verifyChain(realm)).toEqual({
        ok: false,
        realmId: realm,
        from: { seq: 0n, hash: GENESIS_HEX },
        rowsChecked: 2,
        break: { id: rows[3].id, seq: BigInt(rows[3].seq), reason: 'prev_hash_mismatch' },
      });
    });

    it('fails at the next row when a row was hidden from the chain or turned into a user event', async () => {
      const realm = randomUUID();
      const rows = await fiveRows(realm);
      await tamper([
        [
          `UPDATE events SET category = 'user', prev_hash = NULL, hash = NULL WHERE id = $1`,
          [rows[1].id],
        ],
      ]);

      expect(await store.verifyChain(realm)).toMatchObject({
        ok: false,
        break: { id: rows[2].id, reason: 'prev_hash_mismatch' },
      });
    });

    // A head kept outside the database catches what the chain alone cannot.
    it('fails from a kept head when the chain was cut back to before it', async () => {
      const realm = randomUUID();
      const rows = await fiveRows(realm);
      const kept = await store.verifyChain(realm);
      if (!kept.ok || !kept.head) throw new Error('expected a head');
      await pool().query('DELETE FROM events WHERE realm_id = $1 AND seq >= $2', [
        realm,
        rows[3].seq,
      ]);

      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 3 });
      expect(await store.verifyChain(realm, kept.head)).toEqual({
        ok: false,
        realmId: realm,
        from: { seq: kept.head.seq, hash: kept.head.hash },
        rowsChecked: 0,
        break: { id: null, seq: kept.head.seq, reason: 'anchor_missing' },
      });
    });

    it('fails from a kept head when that head was edited, or the chain rewritten up to it', async () => {
      const realm = randomUUID();
      const rows = await fiveRows(realm);
      const kept = await store.verifyChain(realm);
      if (!kept.ok || !kept.head) throw new Error('expected a head');
      await tamper([[`UPDATE events SET actor_id = 'someone-else' WHERE id = $1`, [rows[4].id]]]);
      expect(await store.verifyChain(realm, kept.head)).toMatchObject({
        ok: false,
        break: { id: rows[4].id, reason: 'anchor_mismatch' },
      });

      await tamper([
        [`UPDATE events SET hash = $2 WHERE id = $1`, [rows[4].id, Buffer.alloc(32, 3)]],
      ]);
      expect(await store.verifyChain(realm, kept.head)).toMatchObject({
        ok: false,
        break: { id: rows[4].id, reason: 'anchor_mismatch' },
      });
    });

    it('reports a row it cannot read back as unreadable', async () => {
      const realm = randomUUID();
      const rows = await fiveRows(realm);
      await tamper([[`UPDATE events SET schema_version = 9 WHERE id = $1`, [rows[4].id]]]);

      expect(await store.verifyChain(realm)).toMatchObject({
        ok: false,
        rowsChecked: 4,
        break: { id: rows[4].id, reason: 'unreadable_row' },
      });
    });
  });

  describe('what the database refuses', () => {
    // The acceptance criterion of #459: the update trigger blocks everyone.
    it('refuses every UPDATE on events, the owner and the superuser included, even one that matches nothing', async () => {
      const realm = randomUUID();
      const id = await emitInTx(change(realm));

      for (const statement of [
        `UPDATE events SET data = '{}'::jsonb WHERE id = '${id}'`,
        `UPDATE events SET hash = hash`,
        `UPDATE events SET data = data WHERE false`,
      ]) {
        await expect(pool().query(statement)).rejects.toMatchObject({
          code: '23514',
          constraint: 'events_no_update',
        });
      }
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 1 });
    });

    it('pins the search_path of the trigger functions', async () => {
      const { rows } = await pool().query(
        `SELECT proname, proconfig FROM pg_proc
          WHERE proname IN ('events_no_update', 'events_admin_follows_head') ORDER BY proname`
      );
      expect(rows).toEqual([
        { proname: 'events_admin_follows_head', proconfig: ['search_path=pg_catalog, pg_temp'] },
        { proname: 'events_no_update', proconfig: ['search_path=pg_catalog, pg_temp'] },
      ]);
    });

    it('refuses an admin row without a hash, a user row with one, and a row off the chain head', async () => {
      const realm = randomUUID();
      await emitInTx(change(realm));
      const [head] = await chainRows(realm);
      const insert = (category: string, prev: Buffer | null, hash: Buffer | null) =>
        pool().query(
          `INSERT INTO events (id, realm_id, category, type, time, data, schema_version, prev_hash, hash)
           VALUES (uuidv7(), $1, $2, 'urn:qauth:event:admin.change_applied:v1-rc.0', 0, '{}', 1, $3, $4)`,
          [realm, category, prev, hash]
        );

      await expect(insert('admin', null, null)).rejects.toMatchObject({
        constraint: 'events_admin_chained',
      });
      await expect(insert('user', head.hash, Buffer.alloc(32, 7))).rejects.toMatchObject({
        constraint: 'events_admin_chained',
      });
      // A second row after the genesis, a fork, and a row at a made-up hash.
      for (const prev of [head.prev_hash, Buffer.alloc(32, 9)]) {
        await expect(insert('admin', prev, Buffer.alloc(32, 7))).rejects.toMatchObject({
          code: '23514',
          constraint: 'events_admin_follows_head',
        });
      }
      await expect(insert('admin', head.hash, Buffer.alloc(31))).rejects.toMatchObject({
        constraint: 'events_hash_sha256',
      });
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 1 });
    });

    it('refuses an admin row whose seq was not the identity, so none can hold the head forever', async () => {
      const realm = randomUUID();
      await emitInTx(change(realm));
      const [head] = await chainRows(realm);

      await expect(
        pool().query(
          `INSERT INTO events (seq, id, realm_id, category, type, time, data, schema_version, prev_hash, hash)
           OVERRIDING SYSTEM VALUE
           VALUES (4611686018427387904, uuidv7(), $1, 'admin', 'urn:qauth:event:admin.change_applied:v1-rc.0', 0, '{}', 1, $2, $3)`,
          [realm, head.hash, Buffer.alloc(32, 7)]
        )
      ).rejects.toMatchObject({ code: '23514', constraint: 'events_seq_from_identity' });
      await emitInTx(change(realm));
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 2 });
    });

    it('refuses an admin row that follows the head with a seq below it, so later writers are not locked out', async () => {
      const realm = randomUUID();
      await emitInTx(change(realm));
      const [head] = await chainRows(realm);
      const { rows } = await pool().query<{ seq: string }>(
        `SELECT seq::text FROM events WHERE realm_id = $1 AND hash IS NOT NULL`,
        [realm]
      );
      const below = BigInt(rows[0].seq) - 1n;

      // An unused seq below the head's, with the head's hash as prev_hash:
      // kept, it would leave the head where it was, and every later writer
      // would follow that head into idx_events_chain_link.
      for (const seq of [below, 0n]) {
        await expect(
          pool().query(
            `INSERT INTO events (seq, id, realm_id, category, type, time, data, schema_version, prev_hash, hash)
             OVERRIDING SYSTEM VALUE
             VALUES ($4, uuidv7(), $1, 'admin', 'urn:qauth:event:admin.change_applied:v1-rc.0', 0, '{}', 1, $2, $3)`,
            [realm, head.hash, Buffer.alloc(32, 7), seq.toString()]
          )
        ).rejects.toMatchObject({ code: '23514', constraint: 'events_seq_from_identity' });
      }
      await emitInTx(change(realm));
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 2 });
    });

    it('turns a REPEATABLE READ writer that read a stale head into a unique violation, not a fork', async () => {
      const realm = randomUUID();
      await emitInTx(change(realm));
      const snapshotTaken = gate();
      const otherCommitted = gate();

      const stale = db().transaction(
        async (tx: DbTransaction) => {
          // The snapshot is taken here, before the other writer commits.
          await tx.execute(sql`select 1`);
          snapshotTaken.open();
          await otherCommitted.promise;
          return store.emitAdminEvent(tx, change(realm));
        },
        { isolationLevel: 'repeatable read' }
      );
      await snapshotTaken.promise;
      await emitInTx(change(realm));
      otherCommitted.open();

      expect(await sqlState(stale)).toBe('23505');
      expect(await chainRows(realm)).toHaveLength(2);
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 2 });
    });
  });

  describe('what an admin event stores', () => {
    // The acceptance criterion of #459, on a stored row: known secret field
    // names show *** in the event.
    it('stores *** for a client secret hash, a signing key, a webhook secret and an SMTP password', async () => {
      const realm = randomUUID();
      const before = {
        clientSecretHash: '$argon2id$v=19$m=19456,t=2,p=1$old',
        signingKey: { kty: 'OKP', crv: 'Ed25519', d: 'old-private' },
        webhookSecret: 'whsec_b2xkLXNlY3JldA==',
        smtpPassword: 'old-smtp-password',
        displayName: 'Notes',
      };
      const after = {
        clientSecretHash: '$argon2id$v=19$m=19456,t=2,p=1$new',
        signingKey: { kty: 'OKP', crv: 'Ed25519', d: 'new-private' },
        webhookSecret: 'whsec_bmV3LXNlY3JldA==',
        smtpPassword: 'new-smtp-password',
        displayName: 'Team notes',
      };
      await emitInTx(change(realm, { target: { type: 'client', id: 'notes' }, before, after }));

      const { rows } = await pool().query(`SELECT data FROM events WHERE realm_id = $1`, [realm]);
      expect(rows[0].data.diff).toEqual([
        { path: '/clientSecretHash', before: '***', after: '***' },
        { path: '/displayName', before: 'Notes', after: 'Team notes' },
        { path: '/signingKey', before: '***', after: '***' },
        { path: '/smtpPassword', before: '***', after: '***' },
        { path: '/webhookSecret', before: '***', after: '***' },
      ]);
      expect(JSON.stringify(rows[0].data)).not.toMatch(/argon2id|private|whsec_|smtp-password/);
    });

    it('returns both approvals of a two-admin operation, with their credential ids, in the envelope', async () => {
      const realm = randomUUID();
      const approvals = [
        {
          approverId: randomUUID(),
          credentialId: 'credential-of-the-requester',
          approverCreatedBy: { type: 'operator_cli' as const, id: 'root' },
          approvedAt: '2026-10-24T09:00:00.000Z',
        },
        {
          approverId: randomUUID(),
          credentialId: 'credential-of-the-second-admin',
          approverCreatedBy: { type: 'user' as const, id: ADMIN_ID },
        },
      ];
      await emitInTx(change(realm, { approvals }));

      const page = await store.readAfter(realm, eventStreamStart(realm), 10);
      expect(page.events[0].event).toMatchObject({
        category: 'admin',
        type: 'urn:qauth:event:admin.change_applied:v1-rc.0',
        data: { approvals },
      });
    });

    // The CLI task of #459: a command-line tool calls the same function as
    // an operator_cli actor with the operating-system user.
    it('records an operator on the server host as operator_cli with the operating-system user', async () => {
      const realm = randomUUID();
      const actor = operatorCliActor();
      await emitInTx(change(realm, { actor }));

      const { rows } = await pool().query(
        `SELECT actor_type, actor_id FROM events WHERE realm_id = $1`,
        [realm]
      );
      expect(rows).toEqual([{ actor_type: 'operator_cli', actor_id: actor.id }]);
      expect(actor.id).not.toBe('');
    });
  });

  describe('a role holding the writer grants', () => {
    const ROLE = 'qauth_events_admin_writer';
    let writer: Pool | undefined;
    let writerStore: EventsRepository;

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      // Login roles are cluster-wide and outlive `reset()`; the container is
      // per file, so creating it once here is enough. The per-role database
      // users come from the topology area; this temporary role stands in.
      await pool().query(`CREATE ROLE ${ROLE} LOGIN PASSWORD '${ROLE}'`);
      await pool().query(`GRANT USAGE ON SCHEMA public TO ${ROLE}`);
      // Twice: the statements are idempotent.
      for (let i = 0; i < 2; i += 1) {
        for (const statement of eventsWriterGrantStatements(ROLE)) await pool().query(statement);
      }
      const url = new URL(ctx.connectionString);
      url.username = ROLE;
      url.password = ROLE;
      writer = new Pool({ connectionString: url.toString(), max: 4 });
      writerStore = createEventsRepository(drizzle(writer) as unknown as Database);
    });

    afterAll(async () => {
      await writer?.end();
    });

    function writerDb(): Database {
      if (!writer) throw new Error('no writer pool');
      return drizzle(writer) as unknown as Database;
    }

    it('holds INSERT and SELECT on events, nothing else', async () => {
      const { rows } = await pool().query(
        `SELECT table_name, privilege_type FROM information_schema.role_table_grants
          WHERE grantee = $1 ORDER BY table_name, privilege_type`,
        [ROLE]
      );
      expect(rows).toEqual([
        { table_name: 'events', privilege_type: 'INSERT' },
        { table_name: 'events', privilege_type: 'SELECT' },
      ]);
    });

    it('can write admin events, in a transaction and in one of its own, and verify the chain', async () => {
      const realm = randomUUID();
      await emitInTx(change(realm), writerStore, writerDb());
      await writerStore.emitInOwnTransaction({
        type: 'urn:qauth:event:client.suspension_lifted:v1-rc.0',
        realm,
        actor: operatorCliActor(),
        subject: { type: 'client', id: 'portal' },
        data: {},
      });

      expect(await writerStore.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 2 });
    });

    // The acceptance criterion of #459: a role with insert and select only
    // cannot update or delete rows in events.
    it('cannot UPDATE, DELETE or TRUNCATE events', async () => {
      const realm = randomUUID();
      const id = await emitInTx(change(realm));

      // 42501 = insufficient_privilege: the grants stop it before the trigger runs.
      for (const statement of [
        `UPDATE events SET data = '{}'::jsonb WHERE id = '${id}'`,
        `DELETE FROM events WHERE id = '${id}'`,
        'TRUNCATE events',
      ]) {
        expect(await sqlState(writer?.query(statement) ?? Promise.resolve())).toBe('42501');
      }
      expect(await store.verifyChain(realm)).toMatchObject({ ok: true, rowsChecked: 1 });
    });
  });
});
