/**
 * Real-Postgres integration tests for the browser session tables (issue
 * #468).
 *
 * The rules under test live in the DDL, so only a database can prove them:
 * the composite foreign key that keeps a session in its user's realm, the
 * cascades from users and clients, the CHECKs, and the partial index the
 * list-by-user query runs on. The sibling unit suite pins the SQL each
 * repository method sends.
 *
 * The client registry (issue #549) is proven here too: one row per session and
 * client, none for a session that is not live, revocation deleting the rows,
 * and the share lock that keeps a code minted during a revocation from
 * leaving a row behind.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { NewSession, SessionsRepository } from '../../types';
import type { DbClient } from '../db';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createSessionsRepository } from './sessions.repository';

const HOUR = 3_600_000;

describe('sessions integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repo: SessionsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repo = createSessionsRepository(ctx.database.db);
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

  async function one(statement: string, params: unknown[] = []): Promise<string> {
    const { rows } = await pool().query(statement, params);
    return rows[0].id as string;
  }

  async function seedRealm(): Promise<string> {
    return one(`INSERT INTO realms (name) VALUES ($1) RETURNING id`, [
      `realm-${Math.random().toString(36).slice(2)}`,
    ]);
  }

  async function seedUser(realmId: string): Promise<string> {
    return one(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [realmId]);
  }

  async function seedClient(realmId: string): Promise<string> {
    return one(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, $2, 'h', 'app', '["https://app.example.com/cb"]')
       RETURNING id`,
      [realmId, `client-${Math.random().toString(36).slice(2)}`]
    );
  }

  function session(realmId: string, userId: string, overrides: Partial<NewSession> = {}) {
    const now = Date.now();
    return {
      realmId,
      userId,
      authTime: now,
      amr: ['pwd'],
      ipAddress: '192.0.2.1',
      userAgent: 'test-agent',
      expiresAt: now + HOUR,
      ...overrides,
    };
  }

  async function count(table: string, where: string, params: unknown[]): Promise<number> {
    const { rows } = await pool().query(
      `SELECT count(*)::int AS n FROM "${table}" WHERE ${where}`,
      params
    );
    return rows[0].n as number;
  }

  describe('realm binding', () => {
    it('refuses a session whose realm differs from its user realm', async () => {
      const realmA = await seedRealm();
      const realmB = await seedRealm();
      const userOfA = await seedUser(realmA);

      await expect(repo.create(session(realmB, userOfA))).rejects.toMatchObject({
        cause: { code: '23503', constraint: 'sessions_user_realm_fk' },
      });
      await expect(
        pool().query(
          `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at) VALUES ($1, $2, 1, 2)`,
          [realmB, userOfA]
        )
      ).rejects.toMatchObject({ code: '23503', constraint: 'sessions_user_realm_fk' });
      expect(await count('sessions', 'true', [])).toBe(0);
    });

    it('refuses to move a session to another realm, and a user with sessions to another realm', async () => {
      const realmA = await seedRealm();
      const realmB = await seedRealm();
      const user = await seedUser(realmA);
      const created = await repo.create(session(realmA, user));

      await expect(
        pool().query(`UPDATE sessions SET realm_id = $1 WHERE id = $2`, [realmB, created.id])
      ).rejects.toMatchObject({ code: '23503', constraint: 'sessions_user_realm_fk' });
      await expect(
        pool().query(`UPDATE users SET realm_id = $1 WHERE id = $2`, [realmB, user])
      ).rejects.toMatchObject({ code: '23503', constraint: 'sessions_user_realm_fk' });
    });

    it('finds, touches, ends and lists a session only in its own realm', async () => {
      const realmA = await seedRealm();
      const realmB = await seedRealm();
      const user = await seedUser(realmA);
      const created = await repo.create(session(realmA, user));

      expect(await repo.findById(realmB, created.id)).toBeUndefined();
      expect(await repo.updateLastSeen(realmB, created.id)).toBe(false);
      expect(await repo.revoke(realmB, created.id, 'admin')).toBeUndefined();
      expect(await repo.listActiveForUser(realmB, user)).toEqual([]);

      expect(await repo.findById(realmA, created.id)).toEqual(created);
    });
  });

  describe('cascades', () => {
    it('deleting a user deletes the user sessions and their client rows', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const other = await seedUser(realm);
      const client = await seedClient(realm);
      const gone = await repo.create(session(realm, user));
      const kept = await repo.create(session(realm, other));
      await pool().query(
        `INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $3), ($2, $3)`,
        [gone.id, kept.id, client]
      );

      await pool().query(`DELETE FROM users WHERE id = $1`, [user]);

      expect(await count('sessions', 'user_id = $1', [user])).toBe(0);
      expect(await count('session_clients', 'session_id = $1', [gone.id])).toBe(0);
      expect(await repo.findById(realm, kept.id)).toEqual(kept);
      expect(await count('session_clients', 'session_id = $1', [kept.id])).toBe(1);
    });

    it('deleting a client deletes its session_clients rows and keeps the sessions', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const gone = await seedClient(realm);
      const kept = await seedClient(realm);
      const created = await repo.create(session(realm, user));
      await pool().query(
        `INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2), ($1, $3)`,
        [created.id, gone, kept]
      );

      await pool().query(`DELETE FROM oauth_clients WHERE id = $1`, [gone]);

      const { rows } = await pool().query(
        `SELECT oauth_client_id FROM session_clients WHERE session_id = $1`,
        [created.id]
      );
      expect(rows).toEqual([{ oauth_client_id: kept }]);
      expect(await repo.findById(realm, created.id)).toEqual(created);
    });

    it('deleting a realm deletes its sessions and their client rows', async () => {
      const realm = await seedRealm();
      const other = await seedRealm();
      const created = await repo.create(session(realm, await seedUser(realm)));
      const kept = await repo.create(session(other, await seedUser(other)));
      await pool().query(
        `INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)`,
        [created.id, await seedClient(realm)]
      );

      await pool().query(`DELETE FROM realms WHERE id = $1`, [realm]);

      expect(await count('sessions', 'realm_id = $1', [realm])).toBe(0);
      expect(await count('session_clients', 'session_id = $1', [created.id])).toBe(0);
      expect(await repo.findById(other, kept.id)).toEqual(kept);
    });

    it('records a client once per session', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const client = await seedClient(realm);
      const created = await repo.create(session(realm, user));
      await pool().query(
        `INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)`,
        [created.id, client]
      );

      await expect(
        pool().query(`INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)`, [
          created.id,
          client,
        ])
      ).rejects.toMatchObject({ code: '23505', constraint: 'session_clients_pk' });
    });
  });

  describe('checks', () => {
    async function seedSession(): Promise<string> {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      return (await repo.create(session(realm, user))).id;
    }

    it('accepts every listed revocation reason and refuses any other', async () => {
      const id = await seedSession();
      for (const reason of [
        'sign_out',
        'sign_out_everywhere',
        'admin',
        'reset',
        'key_retired',
        'browser_limit',
        'idle',
        'expired',
      ]) {
        await pool().query(
          `UPDATE sessions SET revoked_at = 1, revoked_reason = $2 WHERE id = $1`,
          [id, reason]
        );
      }
      await expect(
        pool().query(
          `UPDATE sessions SET revoked_at = 1, revoked_reason = 'logout' WHERE id = $1`,
          [id]
        )
      ).rejects.toMatchObject({ code: '23514', constraint: 'sessions_revoked_reason_valid' });
    });

    it('sets revoked_at and revoked_reason together', async () => {
      const id = await seedSession();

      await expect(
        pool().query(`UPDATE sessions SET revoked_at = 1 WHERE id = $1`, [id])
      ).rejects.toMatchObject({ code: '23514', constraint: 'sessions_revoked_pair' });
      await expect(
        pool().query(`UPDATE sessions SET revoked_reason = 'admin' WHERE id = $1`, [id])
      ).rejects.toMatchObject({ code: '23514', constraint: 'sessions_revoked_pair' });
    });

    it('takes amr as an array and assurance_level as substantial, high or NULL', async () => {
      const id = await seedSession();

      await expect(
        pool().query(`UPDATE sessions SET amr = '"pwd"' WHERE id = $1`, [id])
      ).rejects.toMatchObject({ code: '23514', constraint: 'sessions_amr_is_array' });
      await expect(
        pool().query(`UPDATE sessions SET assurance_level = 'low' WHERE id = $1`, [id])
      ).rejects.toMatchObject({ code: '23514', constraint: 'sessions_assurance_level_valid' });
      for (const level of ['substantial', 'high', null]) {
        await pool().query(`UPDATE sessions SET assurance_level = $2 WHERE id = $1`, [id, level]);
      }
    });

    it('requires auth_time', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);

      await expect(
        pool().query(`INSERT INTO sessions (realm_id, user_id, expires_at) VALUES ($1, $2, 1)`, [
          realm,
          user,
        ])
      ).rejects.toMatchObject({ code: '23502', column: 'auth_time' });
    });
  });

  describe('repository', () => {
    it('creates a live session with a uuidv7 id and the given authentication', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const input = session(realm, user, {
        authTime: 1_800_000_000_000,
        amr: ['hwk', 'user'],
        assuranceLevel: 'high',
      });

      const created = await repo.create(input);

      expect(created.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-/);
      expect(created).toMatchObject({
        realmId: realm,
        userId: user,
        authTime: 1_800_000_000_000,
        amr: ['hwk', 'user'],
        assuranceLevel: 'high',
        ipAddress: '192.0.2.1',
        userAgent: 'test-agent',
        expiresAt: input.expiresAt,
        revokedAt: null,
        revokedReason: null,
      });
    });

    it('writes last_seen_at at most once per interval, and never on an ended session', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const created = await repo.create(session(realm, user));
      await pool().query(`UPDATE sessions SET last_seen_at = $2 WHERE id = $1`, [
        created.id,
        Date.now() - 2 * 60_000,
      ]);

      // Several nodes touch the session in the same interval: one writes.
      const writes = await Promise.all(
        Array.from({ length: 5 }, () =>
          repo.updateLastSeen(realm, created.id, { minIntervalMs: 60_000 })
        )
      );
      expect(writes.filter(Boolean)).toHaveLength(1);
      const seen = (await repo.findById(realm, created.id))?.lastSeenAt ?? 0;
      expect(Date.now() - seen).toBeLessThan(60_000);

      const expired = await repo.create(session(realm, user, { expiresAt: Date.now() - 1 }));
      expect(await repo.updateLastSeen(realm, expired.id)).toBe(false);

      await repo.revoke(realm, created.id, 'sign_out');
      expect(await repo.updateLastSeen(realm, created.id)).toBe(false);
    });

    it('revokes a session once and keeps the first reason', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const created = await repo.create(session(realm, user));

      const ended = await repo.revoke(realm, created.id, 'sign_out_everywhere');
      expect(ended?.session).toMatchObject({
        id: created.id,
        revokedReason: 'sign_out_everywhere',
      });
      expect(ended?.session.revokedAt).toEqual(expect.any(Number));
      expect(ended?.clients).toEqual([]);

      expect(await repo.revoke(realm, created.id, 'admin')).toBeUndefined();
      expect(await repo.findById(realm, created.id)).toEqual(ended?.session);
    });

    it('lists only the user live sessions, newest first', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const other = await seedUser(realm);
      const older = await repo.create(session(realm, user));
      const newer = await repo.create(session(realm, user));
      const revoked = await repo.create(session(realm, user));
      await repo.revoke(realm, revoked.id, 'sign_out');
      await repo.create(session(realm, user, { expiresAt: Date.now() - 1 }));
      await repo.create(session(realm, other));

      const listed = await repo.listActiveForUser(realm, user);

      expect(listed.map((s) => s.id)).toEqual([newer.id, older.id]);
    });
  });

  describe('active-session index', () => {
    /** Every index a plan node scans, depth first. */
    function indexNames(plan: Record<string, unknown>): string[] {
      const own = typeof plan['Index Name'] === 'string' ? [plan['Index Name'] as string] : [];
      const children = (plan['Plans'] as Record<string, unknown>[] | undefined) ?? [];
      return [...own, ...children.flatMap(indexNames)];
    }

    function nodeTypes(plan: Record<string, unknown>): string[] {
      const children = (plan['Plans'] as Record<string, unknown>[] | undefined) ?? [];
      return [plan['Node Type'] as string, ...children.flatMap(nodeTypes)];
    }

    it('serves the list-by-user query', async () => {
      // Two realms of 500 users, each with ten sessions of which eight are
      // revoked: enough rows that the planner prefers an index, and enough
      // revoked ones that the partial index is the narrower choice.
      const realmA = await seedRealm();
      const realmB = await seedRealm();
      const now = Date.now();
      for (const realm of [realmA, realmB]) {
        await pool().query(`INSERT INTO users (realm_id) SELECT $1 FROM generate_series(1, 500)`, [
          realm,
        ]);
      }
      await pool().query(
        `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at, revoked_at, revoked_reason)
         SELECT u.realm_id, u.id, $1, $2,
                CASE WHEN g <= 8 THEN $1::bigint END,
                CASE WHEN g <= 8 THEN 'sign_out' END
           FROM users u CROSS JOIN generate_series(1, 10) g`,
        [now, now + HOUR]
      );
      await pool().query('ANALYZE users; ANALYZE sessions');
      const user = await one(`SELECT id FROM users WHERE realm_id = $1 LIMIT 1`, [realmA]);

      // Run the repository's own statement through a client that records it.
      const captured: { text: string; values: unknown[] }[] = [];
      const recording = {
        query: (config: { text: string; values?: unknown[] }, values?: unknown[]) => {
          captured.push({ text: config.text, values: config.values ?? values ?? [] });
          return pool().query(config, values);
        },
      };
      const recorded = createSessionsRepository(
        drizzle(recording as unknown as Pool) as unknown as DbClient
      );
      expect(await recorded.listActiveForUser(realmA, user)).toHaveLength(2);
      expect(captured).toHaveLength(1);

      const { rows } = await pool().query(
        `EXPLAIN (FORMAT JSON) ${captured[0].text}`,
        captured[0].values
      );
      const plan = rows[0]['QUERY PLAN'][0].Plan as Record<string, unknown>;

      expect(indexNames(plan)).toEqual(['idx_sessions_realm_user_active']);
      expect(nodeTypes(plan)).not.toContain('Seq Scan');
    });
  });

  describe('client registry (#549)', () => {
    function db(): DbClient {
      if (!ctx) throw new Error('no ctx');
      return ctx.database.db;
    }

    /** `recordClient` in a transaction of its own, as a code mint runs it. */
    function record(realmId: string, sessionId: string, clientId: string): Promise<boolean> {
      return db().transaction((tx) => repo.recordClient(realmId, sessionId, clientId, tx));
    }

    async function registry(sessionId: string): Promise<{ oauth_client_id: string }[]> {
      const { rows } = await pool().query(
        `SELECT oauth_client_id FROM session_clients WHERE session_id = $1 ORDER BY oauth_client_id`,
        [sessionId]
      );
      return rows;
    }

    it('records a client once per live session and keeps the first time', async () => {
      const realm = await seedRealm();
      const created = await repo.create(session(realm, await seedUser(realm)));
      const client = await seedClient(realm);

      expect(await record(realm, created.id, client)).toBe(true);
      const [first] = await repo.listClientsForSession(realm, created.id);
      expect(await record(realm, created.id, client)).toBe(true);

      expect(await repo.listClientsForSession(realm, created.id)).toEqual([first]);
      expect(first).toEqual({
        sessionId: created.id,
        oauthClientId: client,
        firstSeenAt: expect.any(Number),
      });
    });

    it('records nothing for a revoked or expired session, one of another realm, or a client of another realm', async () => {
      const realm = await seedRealm();
      const other = await seedRealm();
      const user = await seedUser(realm);
      const client = await seedClient(realm);
      const foreignClient = await seedClient(other);
      const revoked = await repo.create(session(realm, user));
      await repo.revoke(realm, revoked.id, 'sign_out');
      const expired = await repo.create(session(realm, user, { expiresAt: Date.now() - 1 }));
      const live = await repo.create(session(realm, user));

      expect(await record(realm, revoked.id, client)).toBe(false);
      expect(await record(realm, expired.id, client)).toBe(false);
      expect(await record(other, live.id, client)).toBe(false);
      expect(await record(realm, live.id, foreignClient)).toBe(false);
      expect(await count('session_clients', 'true', [])).toBe(0);
      // The live session and a client of its realm: recorded.
      expect(await record(realm, live.id, client)).toBe(true);
    });

    it('revoking a session deletes and returns its rows, and leaves other sessions’ rows', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const clientA = await seedClient(realm);
      const clientB = await seedClient(realm);
      const ended = await repo.create(session(realm, user));
      const kept = await repo.create(session(realm, user));
      await record(realm, ended.id, clientA);
      await record(realm, ended.id, clientB);
      await record(realm, kept.id, clientA);

      const revoked = await repo.revoke(realm, ended.id, 'sign_out');
      expect(revoked?.session.id).toBe(ended.id);
      expect(revoked?.clients.map((row) => row.oauthClientId).sort()).toEqual(
        [clientA, clientB].sort()
      );
      expect(revoked?.clients.every((row) => row.sessionId === ended.id)).toBe(true);

      expect(await registry(ended.id)).toEqual([]);
      expect(await registry(kept.id)).toEqual([{ oauth_client_id: clientA }]);
      // The session row stays, soft-ended, until a purge deletes it.
      expect(await repo.findById(realm, ended.id)).toMatchObject({ revokedReason: 'sign_out' });
    });

    it('a revocation that waits on a code mint deletes and returns the row the mint wrote', async () => {
      const realm = await seedRealm();
      const created = await repo.create(session(realm, await seedUser(realm)));
      const client = await seedClient(realm);
      let revocation: ReturnType<SessionsRepository['revoke']> | undefined;

      await db().transaction(async (tx) => {
        expect(await repo.recordClient(realm, created.id, client, tx)).toBe(true);
        revocation = repo.revoke(realm, created.id, 'sign_out');
        // The revocation's UPDATE queues behind the share lock this
        // transaction holds.
        await waitForLockWait();
      });
      const revoked = await revocation;
      expect(revoked?.session.id).toBe(created.id);
      // The client the mint served is in the list back-channel logout reads.
      expect(revoked?.clients).toEqual([
        { sessionId: created.id, oauthClientId: client, firstSeenAt: expect.any(Number) },
      ]);

      expect(await registry(created.id)).toEqual([]);
    });

    it('a code mint that waits on a revocation records nothing', async () => {
      const realm = await seedRealm();
      const created = await repo.create(session(realm, await seedUser(realm)));
      const client = await seedClient(realm);
      let mint: Promise<boolean> | undefined;

      await db().transaction(async (tx) => {
        expect((await repo.revoke(realm, created.id, 'sign_out', tx))?.session.id).toBe(created.id);
        mint = record(realm, created.id, client);
        await waitForLockWait();
      });

      expect(await mint).toBe(false);
      expect(await registry(created.id)).toEqual([]);
    });

    /** Resolve once some backend is waiting on a row lock. */
    async function waitForLockWait(): Promise<void> {
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline) {
        const { rows } = await pool().query(
          `SELECT count(*)::int AS n FROM pg_stat_activity WHERE wait_event_type = 'Lock'`
        );
        if ((rows[0].n as number) > 0) return;
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      throw new Error('no backend waited on a lock');
    }

    it('looks the registry up by session, by user and by client, within the realm', async () => {
      const realm = await seedRealm();
      const other = await seedRealm();
      const alice = await seedUser(realm);
      const bob = await seedUser(realm);
      const app = await seedClient(realm);
      const tool = await seedClient(realm);
      const aliceFirst = await repo.create(session(realm, alice));
      const aliceSecond = await repo.create(session(realm, alice));
      const bobs = await repo.create(session(realm, bob));
      const elsewhere = await repo.create(session(other, await seedUser(other)));
      const foreignClient = await seedClient(other);
      // Explicit times, so the order is the registry's and not the clock's.
      await pool().query(
        `INSERT INTO session_clients (session_id, oauth_client_id, first_seen_at)
         VALUES ($1, $4, 1000), ($1, $5, 2000), ($2, $4, 3000), ($3, $4, 4000), ($6, $7, 500)`,
        [aliceFirst.id, aliceSecond.id, bobs.id, app, tool, elsewhere.id, foreignClient]
      );
      const row = (sessionId: string, oauthClientId: string, firstSeenAt: number) => ({
        sessionId,
        oauthClientId,
        firstSeenAt,
      });

      expect(await repo.listClientsForSession(realm, aliceFirst.id)).toEqual([
        row(aliceFirst.id, app, 1000),
        row(aliceFirst.id, tool, 2000),
      ]);
      expect(await repo.listClientsForUser(realm, alice)).toEqual([
        row(aliceFirst.id, app, 1000),
        row(aliceFirst.id, tool, 2000),
        row(aliceSecond.id, app, 3000),
      ]);
      expect(await repo.listSessionsForClient(realm, app)).toEqual([
        row(aliceFirst.id, app, 1000),
        row(aliceSecond.id, app, 3000),
        row(bobs.id, app, 4000),
      ]);

      // A session past its end, or revoked by a release that left its rows
      // (the previous one, during a rolling upgrade), is not listed.
      const expired = await repo.create(session(realm, alice, { expiresAt: Date.now() + HOUR }));
      const leftOver = await repo.create(session(realm, alice));
      await pool().query(
        `INSERT INTO session_clients (session_id, oauth_client_id, first_seen_at)
         VALUES ($1, $3, 5000), ($2, $3, 6000)`,
        [expired.id, leftOver.id, app]
      );
      await pool().query(`UPDATE sessions SET expires_at = $2 WHERE id = $1`, [
        expired.id,
        Date.now() - 1,
      ]);
      await pool().query(
        `UPDATE sessions SET revoked_at = $2, revoked_reason = 'sign_out' WHERE id = $1`,
        [leftOver.id, Date.now()]
      );
      expect(await repo.listClientsForSession(realm, expired.id)).toEqual([]);
      expect(await repo.listClientsForSession(realm, leftOver.id)).toEqual([]);
      expect((await repo.listClientsForUser(realm, alice)).map((r) => r.firstSeenAt)).toEqual([
        1000, 2000, 3000,
      ]);
      expect((await repo.listSessionsForClient(realm, app)).map((r) => r.firstSeenAt)).toEqual([
        1000, 3000, 4000,
      ]);

      // Another realm's session and client are never found from this realm.
      expect(await repo.listClientsForSession(realm, elsewhere.id)).toEqual([]);
      expect(await repo.listSessionsForClient(realm, foreignClient)).toEqual([]);
      expect(await repo.listClientsForSession(other, aliceFirst.id)).toEqual([]);
      expect(await repo.listClientsForUser(other, alice)).toEqual([]);
    });

    it('deleting a session clears the session of its codes and keeps the codes', async () => {
      const realm = await seedRealm();
      const user = await seedUser(realm);
      const client = await seedClient(realm);
      const created = await repo.create(session(realm, user));
      const code = await one(
        `INSERT INTO authorization_codes
           (code, oauth_client_id, user_id, redirect_uri, code_challenge, session_id, expires_at)
         VALUES ('code-1', $1, $2, 'https://app.example.com/cb', 'c', $3, $4) RETURNING id`,
        [client, user, created.id, Date.now() + 60_000]
      );

      await pool().query(`DELETE FROM sessions WHERE id = $1`, [created.id]);

      const { rows } = await pool().query(
        `SELECT id, session_id FROM authorization_codes WHERE id = $1`,
        [code]
      );
      expect(rows).toEqual([{ id: code, session_id: null }]);
    });
  });
});
