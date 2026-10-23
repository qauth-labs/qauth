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
      expect(ended).toMatchObject({ id: created.id, revokedReason: 'sign_out_everywhere' });
      expect(ended?.revokedAt).toEqual(expect.any(Number));

      expect(await repo.revoke(realm, created.id, 'admin')).toBeUndefined();
      expect(await repo.findById(realm, created.id)).toEqual(ended);
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
});
