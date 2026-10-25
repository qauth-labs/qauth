/**
 * Seed-then-migrate test for migration 0038: the refresh-token family's start
 * time (ADR-019 Decision 3, #552).
 *
 * Every refresh token from before the migration gets the `created_at` of the
 * earliest token of its family, so a realm's `sso_max_lifespan` counts from the
 * code exchange or sign-in that started the family. From then on an insert
 * without a value, as the previous release makes during a rolling upgrade,
 * takes the start of the family it joins, or now for a new family.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0037, then 0038, so a later migration cannot change
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

const MIGRATION_IDX = 38;

const FAMILY_A = '0199f9a1-0000-7000-8000-00000000000a';
const FAMILY_B = '0199f9a1-0000-7000-8000-00000000000b';

describe('migration 0038 — refresh-token family start (seed-then-migrate)', () => {
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

  /** A realm, a user and a client, as 0037 left them. */
  async function seedOwner(): Promise<{ userId: string; clientId: string }> {
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
    return { userId: user.id, clientId: client.id };
  }

  /** One refresh token as 0037 stored it, with the creation time given. */
  async function seedToken(
    owner: { userId: string; clientId: string },
    hashChar: string,
    familyId: string,
    createdAt: number
  ): Promise<void> {
    await db().query(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, family_id, expires_at, created_at)
       VALUES (repeat($1, 64), $2, $3, $4, $5, $6)`,
      [hashChar, owner.userId, owner.clientId, familyId, createdAt + 1_000_000, createdAt]
    );
  }

  it('gives every token the creation time of the earliest token of its family', async () => {
    const owner = await seedOwner();
    // Family A rotated twice; its rows are inserted out of order, so the
    // backfill cannot lean on insertion order. Family B is a single token.
    await seedToken(owner, 'b', FAMILY_A, 1_700_000_002_000);
    await seedToken(owner, 'a', FAMILY_A, 1_700_000_000_000);
    await seedToken(owner, 'c', FAMILY_A, 1_700_000_005_000);
    await seedToken(owner, 'd', FAMILY_B, 1_700_000_003_000);
    await migrate();

    const { rows } = await db().query<{
      token_hash: string;
      family_created_at: string;
    }>(
      `SELECT left(token_hash, 1) AS token_hash, family_created_at
       FROM refresh_tokens ORDER BY token_hash`
    );
    expect(rows).toEqual([
      { token_hash: 'a', family_created_at: '1700000000000' },
      { token_hash: 'b', family_created_at: '1700000000000' },
      { token_hash: 'c', family_created_at: '1700000000000' },
      { token_hash: 'd', family_created_at: '1700000003000' },
    ]);
  });

  it('adds a bigint column that is required and has no default', async () => {
    await migrate();

    const { rows } = await db().query(
      `SELECT data_type, is_nullable, column_default
       FROM information_schema.columns
       WHERE table_name = 'refresh_tokens' AND column_name = 'family_created_at'`
    );
    expect(rows).toEqual([{ data_type: 'bigint', is_nullable: 'NO', column_default: null }]);
  });

  it('gives a token inserted without a start the start of the family it joins', async () => {
    const owner = await seedOwner();
    await seedToken(owner, 'a', FAMILY_A, 1_700_000_000_000);
    await migrate();

    // The previous release's rotation, as it runs during a rolling upgrade:
    // the same insert as before the migration, with no family_created_at.
    await seedToken(owner, 'b', FAMILY_A, 1_700_000_009_000);

    const { rows } = await db().query(
      `SELECT left(token_hash, 1) AS token_hash, family_created_at
       FROM refresh_tokens ORDER BY token_hash`
    );
    expect(rows).toEqual([
      { token_hash: 'a', family_created_at: '1700000000000' },
      { token_hash: 'b', family_created_at: '1700000000000' },
    ]);
  });

  it('starts a new family now when the insert names neither a known family nor a start', async () => {
    const owner = await seedOwner();
    await migrate();

    const before = Date.now();
    await seedToken(owner, 'c', FAMILY_B, 1_700_000_000_000);
    const after = Date.now();

    const {
      rows: [row],
    } = await db().query<{ family_created_at: string }>(
      'SELECT family_created_at FROM refresh_tokens WHERE family_id = $1',
      [FAMILY_B]
    );
    // Whole seconds, rounded, as the schema's `created_at` defaults are.
    expect(Number(row.family_created_at)).toBeGreaterThanOrEqual(Math.floor(before / 1000) * 1000);
    expect(Number(row.family_created_at)).toBeLessThanOrEqual(Math.ceil(after / 1000) * 1000);
  });

  it('keeps the start an insert names, even inside a known family', async () => {
    const owner = await seedOwner();
    await seedToken(owner, 'a', FAMILY_A, 1_700_000_000_000);
    await migrate();

    await db().query(
      `INSERT INTO refresh_tokens
         (token_hash, user_id, oauth_client_id, family_id, family_created_at, expires_at)
       VALUES (repeat('d', 64), $1, $2, $3, 1700000004000, 1)`,
      [owner.userId, owner.clientId, FAMILY_A]
    );

    const { rows } = await db().query(
      `SELECT family_created_at FROM refresh_tokens WHERE token_hash = repeat('d', 64)`
    );
    expect(rows).toEqual([{ family_created_at: '1700000004000' }]);
  });
});
