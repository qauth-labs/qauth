/**
 * Seed-then-migrate test for migration 0039: the link from a refresh-token
 * family to the authorization code that started it (ADR-017 Decision 10, #627).
 *
 * A code and a refresh token created before the migration come out of it
 * unlinked, so nothing they did changes. From then on the database refuses a
 * link to a code that does not exist and a second family for one code, and
 * deleting a code clears the link while the family lives on.
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

describe('migration 0039 — refresh family to authorization code link (seed-then-migrate)', () => {
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

  /** A realm, a user, a client, a redeemed code and its refresh token, as 0038 left them. */
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
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, expires_at, used)
       VALUES ('code-1', $1, $2, 'https://app.example.com/cb', 'challenge', 1, true) RETURNING id`,
      [client.id, user.id]
    );
    const {
      rows: [refresh],
    } = await db().query<{ id: string }>(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, expires_at, family_created_at)
       VALUES (repeat('a', 64), $1, $2, 1, 1) RETURNING id`,
      [user.id, client.id]
    );
    return { userId: user.id, clientId: client.id, codeId: code.id, refreshId: refresh.id };
  }

  /** Insert a refresh token linked to `codeId`. */
  function insertLinked(
    seeded: { userId: string; clientId: string },
    tokenHash: string,
    codeId: string
  ) {
    return db().query(
      `INSERT INTO refresh_tokens
         (token_hash, user_id, oauth_client_id, expires_at, family_created_at, authorization_code_id)
       VALUES ($1, $2, $3, 1, 1, $4)`,
      [tokenHash, seeded.userId, seeded.clientId, codeId]
    );
  }

  it('leaves a refresh token from before it unlinked', async () => {
    const seeded = await seedGrant();
    await migrate();

    const { rows } = await db().query(
      'SELECT authorization_code_id FROM refresh_tokens WHERE id = $1',
      [seeded.refreshId]
    );
    expect(rows).toEqual([{ authorization_code_id: null }]);
  });

  it('adds a nullable uuid column with no default', async () => {
    await migrate();
    const { rows } = await db().query(
      `SELECT data_type, is_nullable, column_default FROM information_schema.columns
       WHERE table_name = 'refresh_tokens' AND column_name = 'authorization_code_id'`
    );
    expect(rows).toEqual([{ data_type: 'uuid', is_nullable: 'YES', column_default: null }]);
  });

  it('refuses a link to a code that does not exist', async () => {
    const seeded = await seedGrant();
    await migrate();

    await expect(
      insertLinked(seeded, 'b'.repeat(64), '0192f1c4-0000-7000-8000-000000000000')
    ).rejects.toMatchObject({
      code: '23503',
      constraint: 'refresh_tokens_authorization_code_id_authorization_codes_id_fk',
    });
  });

  it('allows one family per code, and any number of unlinked tokens', async () => {
    const seeded = await seedGrant();
    await migrate();

    await insertLinked(seeded, 'b'.repeat(64), seeded.codeId);
    await expect(insertLinked(seeded, 'c'.repeat(64), seeded.codeId)).rejects.toMatchObject({
      code: '23505',
      constraint: 'idx_refresh_tokens_authorization_code_id',
    });
    await db().query(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, expires_at, family_created_at)
       VALUES (repeat('d', 64), $1, $2, 1, 1)`,
      [seeded.userId, seeded.clientId]
    );
  });

  it('clears the link when the code is deleted and keeps the token', async () => {
    const seeded = await seedGrant();
    await migrate();
    await insertLinked(seeded, 'b'.repeat(64), seeded.codeId);

    await db().query('DELETE FROM authorization_codes WHERE id = $1', [seeded.codeId]);

    const { rows } = await db().query(
      `SELECT authorization_code_id FROM refresh_tokens WHERE token_hash = repeat('b', 64)`
    );
    expect(rows).toEqual([{ authorization_code_id: null }]);
  });
});
