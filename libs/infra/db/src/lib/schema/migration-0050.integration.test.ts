/**
 * Seed-then-migrate test for migration 0050: the scopes the
 * `client_credentials` grant may issue to a client (#891).
 *
 * The migration is forward-only: it adds a nullable column and a CHECK, and
 * rewrites nothing. A client created before it comes out of it unchanged and
 * with no list, which leaves its grant as it was, and the previous release,
 * which does not know the column, keeps creating and updating clients on the
 * new schema during a rolling upgrade. From then on the database holds NULL
 * or a JSON array there, nothing else.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0049, then 0050, so a later migration cannot change
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

const MIGRATION_IDX = 50;

/** Every column of `oauth_clients` but `client_credentials_scopes`, as one row reads them. */
const ROW_WITHOUT_LIST = `to_jsonb(oauth_clients) - 'client_credentials_scopes'`;

describe('migration 0050 — oauth_clients.client_credentials_scopes (seed-then-migrate)', () => {
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

  /** Apply every migration through 0050. */
  async function migrate(): Promise<void> {
    if (!container) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through);
  }

  async function seedRealm(): Promise<string> {
    const {
      rows: [realm],
    } = await db().query<{ id: string }>(`INSERT INTO realms (name) VALUES ('r') RETURNING id`);
    return realm.id;
  }

  /** A client as the previous release writes one: it does not name the new column. */
  async function insertClientAsPreviousRelease(realmId: string, clientId: string): Promise<string> {
    const {
      rows: [client],
    } = await db().query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris, scopes, grant_types)
       VALUES ($1, $2, 'hash', 'Notes', '["https://notes.example.com/cb"]',
               '["openid", "notes:read", "ssf:stream"]',
               '["authorization_code", "refresh_token", "client_credentials"]') RETURNING id`,
      [realmId, clientId]
    );
    return client.id;
  }

  /** Write the column as raw JSON text, or NULL. */
  async function setList(id: string, json: string | null): Promise<void> {
    await db().query(
      `UPDATE oauth_clients SET client_credentials_scopes = $2::jsonb WHERE id = $1`,
      [id, json]
    );
  }

  it('keeps every existing client unchanged, with no list', async () => {
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');
    const {
      rows: [beforeRow],
    } = await db().query<{ row: unknown }>(
      `SELECT ${ROW_WITHOUT_LIST} AS row FROM oauth_clients WHERE id = $1`,
      [id]
    );

    await migrate();

    const {
      rows: [afterRow],
    } = await db().query<{ row: unknown; client_credentials_scopes: unknown }>(
      `SELECT ${ROW_WITHOUT_LIST} AS row, client_credentials_scopes FROM oauth_clients WHERE id = $1`,
      [id]
    );
    expect(afterRow.row).toEqual(beforeRow.row);
    expect(afterRow.client_credentials_scopes).toBeNull();
  });

  it('adds a nullable column with no default, so the previous release keeps writing clients', async () => {
    await migrate();
    const {
      rows: [column],
    } = await db().query<{ is_nullable: string; column_default: string | null; data_type: string }>(
      `SELECT is_nullable, column_default, data_type
         FROM information_schema.columns
        WHERE table_name = 'oauth_clients' AND column_name = 'client_credentials_scopes'`
    );
    expect(column).toEqual({ is_nullable: 'YES', column_default: null, data_type: 'jsonb' });

    // The rolling leg: old code inserts and updates without the column.
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');
    await setList(id, '["ssf:stream"]');
    await db().query(`UPDATE oauth_clients SET name = 'Notes 2' WHERE id = $1`, [id]);
    const {
      rows: [row],
    } = await db().query<{ client_credentials_scopes: unknown }>(
      `SELECT client_credentials_scopes FROM oauth_clients WHERE id = $1`,
      [id]
    );
    expect(row.client_credentials_scopes).toEqual(['ssf:stream']);
  });

  it('holds NULL or a JSON array, and refuses any other JSON value', async () => {
    await migrate();
    const realmId = await seedRealm();
    const id = await insertClientAsPreviousRelease(realmId, 'notes');

    for (const json of [null, '[]', '["ssf:stream"]', '["ssf:stream", "notes:read"]']) {
      await expect(setList(id, json), String(json)).resolves.toBeUndefined();
    }
    for (const json of ['"ssf:stream"', '{"scopes": ["ssf:stream"]}', '1', 'true', 'null']) {
      await expect(setList(id, json), json).rejects.toMatchObject({
        code: '23514',
        constraint: 'oauth_clients_client_credentials_scopes_is_array',
      });
    }
  });
});
