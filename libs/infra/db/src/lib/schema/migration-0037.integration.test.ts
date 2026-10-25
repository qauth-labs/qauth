/**
 * Seed-then-migrate test for migration 0037: DPoP binding (RFC 9449, #480).
 *
 * A client, an authorization code and a refresh token created before the
 * migration come out of it unbound: the client is not DPoP-bound and neither
 * the code nor the refresh token names a key, so every grant behaves as it did.
 * From then on the database refuses a thumbprint that is not 43 characters of
 * base64url, whoever writes it.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0036, then 0037, so a later migration cannot change
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

const MIGRATION_IDX = 37;

/** The RFC 9449 §7.1 example thumbprint: 43 characters of base64url. */
const THUMBPRINT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

describe('migration 0037 — DPoP binding (seed-then-migrate)', () => {
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

  /** A realm, a user, a client, a code and a refresh token, as 0036 left them. */
  async function seedGrant(): Promise<{ clientId: string; codeId: string; refreshId: string }> {
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
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, expires_at)
       VALUES ('code-1', $1, $2, 'https://app.example.com/cb', 'challenge', 1) RETURNING id`,
      [client.id, user.id]
    );
    const {
      rows: [refresh],
    } = await db().query<{ id: string }>(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, expires_at)
       VALUES (repeat('a', 64), $1, $2, 1) RETURNING id`,
      [user.id, client.id]
    );
    return { clientId: client.id, codeId: code.id, refreshId: refresh.id };
  }

  it('leaves a client, a code and a refresh token from before it unbound', async () => {
    const seeded = await seedGrant();
    await migrate();

    const { rows: clients } = await db().query(
      'SELECT dpop_bound_access_tokens FROM oauth_clients WHERE id = $1',
      [seeded.clientId]
    );
    expect(clients).toEqual([{ dpop_bound_access_tokens: false }]);
    const { rows: codes } = await db().query(
      'SELECT dpop_jkt FROM authorization_codes WHERE id = $1',
      [seeded.codeId]
    );
    expect(codes).toEqual([{ dpop_jkt: null }]);
    const { rows: refreshTokens } = await db().query(
      'SELECT cnf_jkt FROM refresh_tokens WHERE id = $1',
      [seeded.refreshId]
    );
    expect(refreshTokens).toEqual([{ cnf_jkt: null }]);
  });

  it('gives the columns the types and defaults the schema declares', async () => {
    await migrate();
    const { rows } = await db().query<{
      table_name: string;
      column_name: string;
      data_type: string;
      character_maximum_length: number | null;
      is_nullable: string;
      column_default: string | null;
    }>(
      `SELECT table_name, column_name, data_type, character_maximum_length, is_nullable, column_default
       FROM information_schema.columns
       WHERE (table_name, column_name) IN (
         ('oauth_clients', 'dpop_bound_access_tokens'),
         ('authorization_codes', 'dpop_jkt'),
         ('refresh_tokens', 'cnf_jkt'))
       ORDER BY table_name`
    );
    expect(rows).toEqual([
      {
        table_name: 'authorization_codes',
        column_name: 'dpop_jkt',
        data_type: 'character varying',
        character_maximum_length: 43,
        is_nullable: 'YES',
        column_default: null,
      },
      {
        table_name: 'oauth_clients',
        column_name: 'dpop_bound_access_tokens',
        data_type: 'boolean',
        character_maximum_length: null,
        is_nullable: 'NO',
        column_default: 'false',
      },
      {
        table_name: 'refresh_tokens',
        column_name: 'cnf_jkt',
        data_type: 'character varying',
        character_maximum_length: 43,
        is_nullable: 'YES',
        column_default: null,
      },
    ]);
  });

  it('stores a thumbprint and refuses anything that is not one', async () => {
    const seeded = await seedGrant();
    await migrate();

    await db().query('UPDATE authorization_codes SET dpop_jkt = $1 WHERE id = $2', [
      THUMBPRINT,
      seeded.codeId,
    ]);
    await db().query('UPDATE refresh_tokens SET cnf_jkt = $1 WHERE id = $2', [
      THUMBPRINT,
      seeded.refreshId,
    ]);

    // Padding, a character outside base64url, and a 42-character value: none
    // is the base64url SHA-256 thumbprint RFC 9449 §6.1 binds a token to.
    for (const value of [
      `${THUMBPRINT.slice(0, 42)}=`,
      `${THUMBPRINT.slice(0, 42)}+`,
      THUMBPRINT.slice(0, 42),
    ]) {
      await expect(
        db().query('UPDATE authorization_codes SET dpop_jkt = $1 WHERE id = $2', [
          value,
          seeded.codeId,
        ])
      ).rejects.toMatchObject({ code: '23514', constraint: 'authorization_codes_dpop_jkt_format' });
      await expect(
        db().query('UPDATE refresh_tokens SET cnf_jkt = $1 WHERE id = $2', [
          value,
          seeded.refreshId,
        ])
      ).rejects.toMatchObject({ code: '23514', constraint: 'refresh_tokens_cnf_jkt_format' });
    }
    // One character too long is refused by the column's length.
    await expect(
      db().query('UPDATE refresh_tokens SET cnf_jkt = $1 WHERE id = $2', [
        `${THUMBPRINT}A`,
        seeded.refreshId,
      ])
    ).rejects.toMatchObject({ code: '22001' });
  });
});
