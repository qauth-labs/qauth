/**
 * Seed-then-migrate test for migration 0065: how and when the user signed in,
 * on authorization codes and refresh-token families (ADR-017 Decision 10,
 * #662).
 *
 * Forward-only: a code and a refresh token created before the migration come
 * out of it unchanged, with no `amr` and, for the token, no `auth_time`, so
 * their tokens carry neither claim. From then on the database keeps `amr` NULL
 * or a non-empty list, and only beside an `auth_time`, and an `auth_time`
 * positive.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0064, then 0065, so a later migration cannot change
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

const MIGRATION_IDX = 65;
const AUTH_TIME = 1_793_900_000_000;

describe('migration 0065 — sign-in methods on codes and refresh families (seed-then-migrate)', () => {
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

  /** The pool; only called from a test that was not skipped. */
  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  /** Apply every migration through 0065. */
  async function migrate(): Promise<void> {
    if (!container) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through);
  }

  /**
   * A realm, a user, a client, a code minted from a browser session (with its
   * `auth_time`) and the refresh token it bought, as 0064 left them.
   */
  async function seedGrant(): Promise<{
    userId: string;
    clientId: string;
    codeId: string;
    refreshId: string;
  }> {
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
      rows: [code],
    } = await db().query<{ id: string }>(
      `INSERT INTO authorization_codes
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, auth_time, expires_at, used)
       VALUES ('code-1', $1, $2, 'https://app.example.com/cb', 'challenge', $3, 1, true) RETURNING id`,
      [client.id, user.id, AUTH_TIME]
    );
    const {
      rows: [refresh],
    } = await db().query<{ id: string }>(
      `INSERT INTO refresh_tokens
         (token_hash, user_id, oauth_client_id, expires_at, family_created_at, authorization_code_id)
       VALUES (repeat('a', 64), $1, $2, 1, 1, $3) RETURNING id`,
      [user.id, client.id, code.id]
    );
    return { userId: user.id, clientId: client.id, codeId: code.id, refreshId: refresh.id };
  }

  /** Insert a code with `authTime` and `amr` (a JSON value, or null). */
  function insertCode(
    seeded: { userId: string; clientId: string },
    code: string,
    authTime: number | null,
    amr: unknown
  ) {
    return db().query(
      `INSERT INTO authorization_codes
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, auth_time, amr, expires_at)
       VALUES ($1, $2, $3, 'https://app.example.com/cb', 'challenge', $4, $5::jsonb, 1)`,
      [code, seeded.clientId, seeded.userId, authTime, amr === null ? null : JSON.stringify(amr)]
    );
  }

  /** Insert a refresh token with `authTime` and `amr` (a JSON value, or null). */
  function insertToken(
    seeded: { userId: string; clientId: string },
    tokenHash: string,
    authTime: number | null,
    amr: unknown
  ) {
    return db().query(
      `INSERT INTO refresh_tokens
         (token_hash, user_id, oauth_client_id, expires_at, family_created_at, auth_time, amr)
       VALUES ($1, $2, $3, 1, 1, $4, $5::jsonb)`,
      [tokenHash, seeded.userId, seeded.clientId, authTime, amr === null ? null : JSON.stringify(amr)]
    );
  }

  it('leaves a code and a refresh token from before it as they were, with no sign-in methods', async () => {
    const seeded = await seedGrant();
    const { rows: codeBefore } = await db().query(
      'SELECT * FROM authorization_codes WHERE id = $1',
      [seeded.codeId]
    );
    const { rows: tokenBefore } = await db().query('SELECT * FROM refresh_tokens WHERE id = $1', [
      seeded.refreshId,
    ]);

    await migrate();

    const { rows: codeAfter } = await db().query(
      'SELECT * FROM authorization_codes WHERE id = $1',
      [seeded.codeId]
    );
    const { rows: tokenAfter } = await db().query('SELECT * FROM refresh_tokens WHERE id = $1', [
      seeded.refreshId,
    ]);
    expect(codeAfter).toEqual([{ ...codeBefore[0], amr: null }]);
    expect(tokenAfter).toEqual([{ ...tokenBefore[0], auth_time: null, amr: null }]);
  });

  it('adds nullable columns with no default', async () => {
    await migrate();
    const { rows } = await db().query(
      `SELECT table_name, column_name, data_type, is_nullable, column_default
       FROM information_schema.columns
       WHERE (table_name = 'authorization_codes' AND column_name = 'amr')
          OR (table_name = 'refresh_tokens' AND column_name IN ('auth_time', 'amr'))
       ORDER BY table_name, column_name`
    );
    expect(rows).toEqual([
      {
        table_name: 'authorization_codes',
        column_name: 'amr',
        data_type: 'jsonb',
        is_nullable: 'YES',
        column_default: null,
      },
      {
        table_name: 'refresh_tokens',
        column_name: 'amr',
        data_type: 'jsonb',
        is_nullable: 'YES',
        column_default: null,
      },
      {
        table_name: 'refresh_tokens',
        column_name: 'auth_time',
        data_type: 'bigint',
        is_nullable: 'YES',
        column_default: null,
      },
    ]);
  });

  it('keeps working for an insert that names none of the new columns, as the previous release writes', async () => {
    const seeded = await seedGrant();
    await migrate();

    await db().query(
      `INSERT INTO authorization_codes
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, auth_time, expires_at)
       VALUES ('code-old-release', $1, $2, 'https://app.example.com/cb', 'challenge', $3, 1)`,
      [seeded.clientId, seeded.userId, AUTH_TIME]
    );
    await db().query(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, expires_at, family_created_at)
       VALUES (repeat('b', 64), $1, $2, 1, 1)`,
      [seeded.userId, seeded.clientId]
    );

    const { rows } = await db().query(
      `SELECT (SELECT amr FROM authorization_codes WHERE code = 'code-old-release') AS code_amr,
              (SELECT auth_time FROM refresh_tokens WHERE token_hash = repeat('b', 64)) AS token_auth_time,
              (SELECT amr FROM refresh_tokens WHERE token_hash = repeat('b', 64)) AS token_amr`
    );
    expect(rows).toEqual([{ code_amr: null, token_auth_time: null, token_amr: null }]);
  });

  it('stores a sign-in: its time and a non-empty list of methods', async () => {
    const seeded = await seedGrant();
    await migrate();

    await insertCode(seeded, 'code-signed-in', AUTH_TIME, ['pwd']);
    await insertToken(seeded, 'c'.repeat(64), AUTH_TIME, ['pwd', 'otp', 'mfa']);
    // A sign-in that proved no method, and one with no sign-in at all.
    await insertCode(seeded, 'code-no-method', AUTH_TIME, null);
    await insertToken(seeded, 'd'.repeat(64), AUTH_TIME, null);

    const { rows } = await db().query(
      `SELECT amr FROM authorization_codes WHERE code = 'code-signed-in'
       UNION ALL SELECT amr FROM refresh_tokens WHERE token_hash = repeat('c', 64)`
    );
    expect(rows).toEqual([{ amr: ['pwd'] }, { amr: ['pwd', 'otp', 'mfa'] }]);
  });

  it.each([
    ['an empty list', AUTH_TIME, []],
    ['a value that is not a list', AUTH_TIME, 'pwd'],
    ['methods with no auth_time', null, ['pwd']],
  ])('refuses a code whose amr is %s', async (_name, authTime, amr) => {
    const seeded = await seedGrant();
    await migrate();

    await expect(insertCode(seeded, 'code-bad', authTime, amr)).rejects.toMatchObject({
      code: '23514',
      constraint: 'authorization_codes_amr_valid',
    });
  });

  it.each([
    ['an empty list', AUTH_TIME, []],
    ['a value that is not a list', AUTH_TIME, { pwd: true }],
    ['methods with no auth_time', null, ['pwd']],
  ])('refuses a refresh token whose amr is %s', async (_name, authTime, amr) => {
    const seeded = await seedGrant();
    await migrate();

    await expect(insertToken(seeded, 'e'.repeat(64), authTime, amr)).rejects.toMatchObject({
      code: '23514',
      constraint: 'refresh_tokens_amr_valid',
    });
  });

  it('refuses a refresh token whose auth_time is not positive', async () => {
    const seeded = await seedGrant();
    await migrate();

    await expect(insertToken(seeded, 'f'.repeat(64), 0, null)).rejects.toMatchObject({
      code: '23514',
      constraint: 'refresh_tokens_auth_time_positive',
    });
  });
});
