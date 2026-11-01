/**
 * Seed-then-migrate tests for migration 0024: the realm key tables
 * (ADR-019 Decision 9, issue #461).
 *
 * 0024 only adds a type and two tables, so the risk is not a backfill but the
 * upgrade itself: a deployment already running 0000–0023, with data in every
 * table, must take 0024 through the same drizzle migrator the migration runner
 * uses, and keep every existing row as it was.
 *
 * Requires Docker; self-skips without it. Each case rebuilds the schema from
 * scratch (DROP SCHEMA CASCADE) inside the suite's one database.
 */
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';

import {
  applyQauthMigrations,
  QAUTH_MIGRATIONS_FOLDER,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const MIGRATION_IDX = 24;

interface JournalEntry {
  idx: number;
  tag: string;
}

/**
 * A copy of the migrations folder that stops before 0024, so the drizzle
 * migrator can bring a database to exactly the schema a deployment runs
 * today and record it in its own journal table.
 */
function migrationsFolderBefore(idx: number): string {
  const journal = JSON.parse(
    readFileSync(path.join(QAUTH_MIGRATIONS_FOLDER, 'meta/_journal.json'), 'utf8')
  ) as { entries: JournalEntry[] };
  const entries = journal.entries.filter((e) => e.idx < idx);

  const folder = mkdtempSync(path.join(tmpdir(), 'qauth-migrations-'));
  mkdirSync(path.join(folder, 'meta'));
  writeFileSync(
    path.join(folder, 'meta/_journal.json'),
    JSON.stringify({ ...journal, entries }, null, 2)
  );
  for (const entry of entries) {
    copyFileSync(
      path.join(QAUTH_MIGRATIONS_FOLDER, `${entry.tag}.sql`),
      path.join(folder, `${entry.tag}.sql`)
    );
  }
  return folder;
}

describe('migration 0024 — realm key tables (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  let previousFolder: string | undefined;
  // Upgrade to 0024 itself, not to the newest migration: a later migration
  // changes the tables and the journal count this suite pins.
  let throughFolder: string | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    pool = new Pool({ connectionString: container.connectionString, max: 2 });
    previousFolder = migrationsFolderBefore(MIGRATION_IDX);
    throughFolder = migrationsFolderBefore(MIGRATION_IDX + 1);
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
    for (const folder of [previousFolder, throughFolder]) {
      if (folder) rmSync(folder, { recursive: true, force: true });
    }
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool || !container || !previousFolder || !throughFolder) {
      testCtx.skip();
      return;
    }
    await pool.query(
      'DROP SCHEMA IF EXISTS drizzle CASCADE; DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
    );
    await applyQauthMigrations(container.connectionString, previousFolder);
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  function connectionString(): string {
    if (!container) throw new Error('no container');
    return container.connectionString;
  }

  /** Apply the migrations up to and including 0024. */
  async function upgradeTo0024(): Promise<void> {
    if (!throughFolder) throw new Error('no migrations folder');
    await applyQauthMigrations(connectionString(), throughFolder);
  }

  async function one(statement: string, params: unknown[] = []): Promise<string> {
    const { rows } = await db().query(statement, params);
    return rows[0].id as string;
  }

  /** One row in every table the schema has before 0024. */
  async function seedEveryTable(): Promise<string> {
    const realmId = await one(`INSERT INTO realms (name) VALUES ('m0024') RETURNING id`);
    const userId = await one(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [realmId]);
    const credentialId = await one(
      `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub, credential_data)
       VALUES ($1, $2, 'password', 'user@example.com', '{"password_hash":"h","email_verified":true}')
       RETURNING id`,
      [userId, realmId]
    );
    await db().query(
      `INSERT INTO user_attributes (user_id, source, attr_key, attr_value, verified)
       VALUES ($1, 'self_reported', 'email', 'user@example.com', true)`,
      [userId]
    );
    await db().query(
      `INSERT INTO email_verification_tokens (token_hash, credential_id, expires_at)
       VALUES ($1, $2, $3)`,
      ['e'.repeat(64), credentialId, Date.now() + 60_000]
    );
    const clientId = await one(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
       VALUES ($1, 'm0024-client', 'h', 'm0024', '["https://app.example.com/cb"]')
       RETURNING id`,
      [realmId]
    );
    await db().query(
      `INSERT INTO api_keys (realm_id, client_id, name, key_hash, prefix, last4)
       VALUES ($1, $2, 'key', 'h', 'qk_m0024', 'abcd')`,
      [realmId, clientId]
    );
    await db().query(
      `INSERT INTO oauth_consents (user_id, oauth_client_id, realm_id) VALUES ($1, $2, $3)`,
      [userId, clientId, realmId]
    );
    await db().query(
      `INSERT INTO authorization_codes
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, expires_at)
       VALUES ('m0024-code', $1, $2, 'https://app.example.com/cb', 'challenge', $3)`,
      [clientId, userId, Date.now() + 60_000]
    );
    await db().query(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, expires_at)
       VALUES ($1, $2, $3, $4)`,
      ['r'.repeat(64), userId, clientId, Date.now() + 60_000]
    );
    await db().query(
      `INSERT INTO audit_logs (user_id, oauth_client_id, event, event_type, success)
       VALUES ($1, $2, 'oauth.token.issued', 'token', true)`,
      [userId, clientId]
    );
    await db().query(
      `INSERT INTO oid4vp_request_states
         (realm_id, state_hash, nonce, verifier_profile, response_mode, dcql_query, expires_at)
       VALUES ($1, $2, 'nonce', 'oid4vp-1.0-base', 'direct_post', '{"credentials":[]}', $3)`,
      [realmId, 's'.repeat(64), Date.now() + 60_000]
    );
    const roleId = await one(
      `INSERT INTO roles (realm_id, name) VALUES ($1, 'm0024') RETURNING id`,
      [realmId]
    );
    await db().query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [userId, roleId]);
    await db().query(`INSERT INTO sessions (user_id, expires_at) VALUES ($1, $2)`, [
      userId,
      Date.now() + 60_000,
    ]);
    return realmId;
  }

  async function publicTables(): Promise<string[]> {
    const { rows } = await db().query(
      `SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name`
    );
    return rows.map((row) => row.table_name as string);
  }

  /** Row count and a digest of every row, per table. */
  async function contents(tables: readonly string[]): Promise<Record<string, unknown>> {
    const result: Record<string, unknown> = {};
    for (const table of tables) {
      const { rows } = await db().query(
        `SELECT count(*)::int AS rows,
                md5(coalesce(string_agg(to_jsonb(t)::text, '|' ORDER BY to_jsonb(t)::text), ''))
                  AS digest
           FROM "${table}" t`
      );
      result[table] = rows[0];
    }
    return result;
  }

  it('applies through the migrator to a database with the current schema and data', async () => {
    await seedEveryTable();
    const tablesBefore = await publicTables();
    const before = await contents(tablesBefore);
    // Every table that exists before 0024 holds a row, so "unchanged" below
    // is checked against real data, not empty tables.
    expect(Object.values(before).every((table) => (table as { rows: number }).rows > 0)).toBe(true);

    await upgradeTo0024();

    const { rows: applied } = await db().query(
      `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`
    );
    expect(applied[0].n).toBe(MIGRATION_IDX + 1);
    expect(await publicTables()).toEqual(
      [...tablesBefore, 'realm_keys', 'realm_public_keys'].sort()
    );
    expect(await contents(tablesBefore)).toEqual(before);
    expect(await contents(['realm_keys', 'realm_public_keys'])).toEqual({
      realm_keys: { rows: 0, digest: expect.any(String) },
      realm_public_keys: { rows: 0, digest: expect.any(String) },
    });
  });

  it('lets an existing realm take keys after the upgrade', async () => {
    const realmId = await seedEveryTable();
    await upgradeTo0024();

    await db().query(
      `INSERT INTO realm_keys
         (realm_id, purpose, algorithm, kid, status, ciphertext, iv, wrapped_dek, kek_ref,
          aad_version, publish_at)
       VALUES ($1, 'token_signing', 'EdDSA', 'kid-1', 'active', '\\x01', '\\x02', '\\x03', 'kek',
          1, $2)`,
      [realmId, Date.now()]
    );
    await db().query(
      `INSERT INTO realm_public_keys
         (realm_id, kid, purpose, algorithm, status, public_jwk, publish_at)
       VALUES ($1, 'kid-1', 'token_signing', 'EdDSA', 'active', '{"kty":"OKP"}', $2)`,
      [realmId, Date.now()]
    );

    const { rows } = await db().query(
      `SELECT k.status, p.public_jwk
         FROM realm_keys k JOIN realm_public_keys p USING (realm_id, kid)
        WHERE k.realm_id = $1`,
      [realmId]
    );
    expect(rows).toEqual([{ status: 'active', public_jwk: { kty: 'OKP' } }]);
  });
});
