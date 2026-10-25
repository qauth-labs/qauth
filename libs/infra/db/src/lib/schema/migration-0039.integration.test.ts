/**
 * Seed-then-migrate test for migration 0039: the browser session behind an
 * authorization code (ADR-019 Decisions 3 and 4, #549).
 *
 * The migration applies to a schema that holds codes and sessions: every
 * existing code keeps its row and gets no session, and an insert without the
 * column, as the previous release makes during a rolling upgrade, still works.
 * From then on a code may name a session, deleting that session sets the
 * column to NULL and keeps the code, and a code cannot name a session that
 * does not exist.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0038, then 0039, so a later migration cannot change
 * what this test sees.
 */
import { rmSync } from 'node:fs';

import {
  applyQauthMigrations,
  qauthMigrationsFolderWithFirst,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const MIGRATION_IDX = 39;
const EXPIRES_AT = 4_000_000_000_000;

describe('migration 0039 — authorization code session (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  const before = qauthMigrationsFolderWithFirst(MIGRATION_IDX);
  const through = qauthMigrationsFolderWithFirst(MIGRATION_IDX + 1);

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    pool = new Pool({ connectionString: container.connectionString, max: 2 });
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
    rmSync(before, { recursive: true, force: true });
    rmSync(through, { recursive: true, force: true });
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool || !container) {
      testCtx.skip();
      return;
    }
    await pool.query(
      'DROP SCHEMA public CASCADE; CREATE SCHEMA public; DROP SCHEMA IF EXISTS drizzle CASCADE;'
    );
    await applyQauthMigrations(container.connectionString, before);
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  async function migrate(): Promise<void> {
    if (!container) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through);
  }

  /** A realm, a user, a client and a live browser session, as 0038 left them. */
  async function seedOwner(): Promise<{ userId: string; clientId: string; sessionId: string }> {
    const {
      rows: [realm],
    } = await db().query<{ id: string }>(`INSERT INTO realms (name) VALUES ('r') RETURNING id`);
    const {
      rows: [user],
    } = await db().query<{ id: string }>(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [
      realm.id,
    ]);
    const {
      rows: [client],
    } = await db().query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, 'app', 'hash', 'App', '["https://app.example.com/cb"]') RETURNING id`,
      [realm.id]
    );
    const {
      rows: [session],
    } = await db().query<{ id: string }>(
      `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at)
       VALUES ($1, $2, 1, $3) RETURNING id`,
      [realm.id, user.id, EXPIRES_AT]
    );
    return { userId: user.id, clientId: client.id, sessionId: session.id };
  }

  /** A code as 0038 and the previous release insert it: no session column. */
  async function seedCode(
    owner: { userId: string; clientId: string },
    code: string
  ): Promise<string> {
    const {
      rows: [row],
    } = await db().query<{ id: string }>(
      `INSERT INTO authorization_codes
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, auth_time, session_expires_at, expires_at)
       VALUES ($1, $2, $3, 'https://app.example.com/cb', 'challenge', 1, $4, $4) RETURNING id`,
      [code, owner.clientId, owner.userId, EXPIRES_AT]
    );
    return row.id;
  }

  async function sessionOf(codeId: string): Promise<string | null | undefined> {
    const { rows } = await db().query<{ session_id: string | null }>(
      `SELECT session_id FROM authorization_codes WHERE id = $1`,
      [codeId]
    );
    return rows[0]?.session_id;
  }

  it('keeps every existing code, with no session', async () => {
    const owner = await seedOwner();
    const first = await seedCode(owner, 'code-a');
    const second = await seedCode(owner, 'code-b');

    await migrate();

    expect(await sessionOf(first)).toBeNull();
    expect(await sessionOf(second)).toBeNull();
  });

  it('lets the previous release insert a code without the column', async () => {
    const owner = await seedOwner();
    await migrate();

    const code = await seedCode(owner, 'code-rolling');

    expect(await sessionOf(code)).toBeNull();
  });

  it('records a code’s session, and deleting the session keeps the code with no session', async () => {
    const owner = await seedOwner();
    await migrate();
    const code = await seedCode(owner, 'code-with-session');
    await db().query(`UPDATE authorization_codes SET session_id = $1 WHERE id = $2`, [
      owner.sessionId,
      code,
    ]);
    expect(await sessionOf(code)).toBe(owner.sessionId);

    await db().query(`DELETE FROM sessions WHERE id = $1`, [owner.sessionId]);

    expect(await sessionOf(code)).toBeNull();
  });

  it('refuses a session that does not exist', async () => {
    const owner = await seedOwner();
    await migrate();
    const code = await seedCode(owner, 'code-dangling');

    await expect(
      db().query(`UPDATE authorization_codes SET session_id = $1 WHERE id = $2`, [
        '0199f9a1-0000-7000-8000-0000000000ff',
        code,
      ])
    ).rejects.toMatchObject({
      code: '23503',
      constraint: 'authorization_codes_session_id_sessions_id_fk',
    });
  });

  it('serves the session delete’s ON DELETE SET NULL from the new index', async () => {
    await migrate();

    const { rows } = await db().query<{ indexdef: string }>(
      `SELECT indexdef FROM pg_indexes WHERE indexname = 'idx_authorization_codes_session_id'`
    );
    expect(rows).toEqual([
      {
        indexdef:
          'CREATE INDEX idx_authorization_codes_session_id ON public.authorization_codes USING btree (session_id)',
      },
    ]);
  });
});
