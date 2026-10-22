/**
 * Seed-then-migrate tests for migration 0025: realm hosts, issuers and the
 * operator flag (ADR-019 Decision 1, issue #470).
 *
 * 0025 adds a table, two columns, CHECKs, partial unique indexes and two
 * triggers. Existing realms keep a NULL issuer and no host; the boot step
 * fills them later (#484). So the risk is the upgrade itself: a deployment
 * with data in every table must take 0025 through the same drizzle migrator
 * the migration runner uses, keep every existing row, and leave each existing
 * realm able to take its issuer and primary host once.
 *
 * Two starting points: 0024, the schema just before this migration, and 0020,
 * the schema the issue was written against, so a deployment several releases
 * behind upgrades in one run.
 *
 * Requires Docker; self-skips without it. Each case rebuilds the schema from
 * scratch (DROP SCHEMA CASCADE) inside one shared container.
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

const MIGRATION_IDX = 25;
/** The last migration when issue #470 was written. */
const ISSUE_BASELINE_IDX = 20;

interface JournalEntry {
  idx: number;
  tag: string;
}

/**
 * A copy of the migrations folder that stops before `idx`, so the drizzle
 * migrator can bring a database to exactly that schema and record it in its
 * own journal table.
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

describe('migration 0025 — realm hosts and issuers (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  let before0025: string | undefined;
  let atIssueBaseline: string | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    pool = new Pool({ connectionString: container.connectionString, max: 2 });
    before0025 = migrationsFolderBefore(MIGRATION_IDX);
    atIssueBaseline = migrationsFolderBefore(ISSUE_BASELINE_IDX + 1);
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
    for (const folder of [before0025, atIssueBaseline]) {
      if (folder) rmSync(folder, { recursive: true, force: true });
    }
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool || !container || !before0025 || !atIssueBaseline) {
      testCtx.skip();
      return;
    }
    await pool.query(
      'DROP SCHEMA IF EXISTS drizzle CASCADE; DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
    );
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  function connectionString(): string {
    if (!container) throw new Error('no container');
    return container.connectionString;
  }

  function folder(which: 'before0025' | 'atIssueBaseline'): string {
    const result = which === 'before0025' ? before0025 : atIssueBaseline;
    if (!result) throw new Error('no migrations folder');
    return result;
  }

  async function one(statement: string, params: unknown[] = []): Promise<string> {
    const { rows } = await db().query(statement, params);
    return rows[0].id as string;
  }

  async function tableExists(table: string): Promise<boolean> {
    const { rows } = await db().query(`SELECT to_regclass($1) IS NOT NULL AS present`, [
      `public.${table}`,
    ]);
    return rows[0].present as boolean;
  }

  /**
   * One row in every table the schema has, and two realms: a deployment that
   * has grown past the default realm must upgrade too.
   */
  async function seedEveryTable(): Promise<string[]> {
    const realmId = await one(`INSERT INTO realms (name) VALUES ('m0025') RETURNING id`);
    const secondRealmId = await one(
      `INSERT INTO realms (name, enabled) VALUES ('m0025-second', false) RETURNING id`
    );
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
       VALUES ($1, 'm0025-client', 'h', 'm0025', '["https://app.example.com/cb"]')
       RETURNING id`,
      [realmId]
    );
    await db().query(
      `INSERT INTO api_keys (realm_id, client_id, name, key_hash, prefix, last4)
       VALUES ($1, $2, 'key', 'h', 'qk_m0025', 'abcd')`,
      [realmId, clientId]
    );
    await db().query(
      `INSERT INTO oauth_consents (user_id, oauth_client_id, realm_id) VALUES ($1, $2, $3)`,
      [userId, clientId, realmId]
    );
    await db().query(
      `INSERT INTO authorization_codes
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, expires_at)
       VALUES ('m0025-code', $1, $2, 'https://app.example.com/cb', 'challenge', $3)`,
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
      `INSERT INTO roles (realm_id, name) VALUES ($1, 'm0025') RETURNING id`,
      [realmId]
    );
    await db().query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [userId, roleId]);
    await db().query(`INSERT INTO sessions (user_id, expires_at) VALUES ($1, $2)`, [
      userId,
      Date.now() + 60_000,
    ]);
    if (await tableExists('realm_keys')) {
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
    }
    return [realmId, secondRealmId];
  }

  async function publicTables(): Promise<string[]> {
    const { rows } = await db().query(
      `SELECT table_name FROM information_schema.tables
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name`
    );
    return rows.map((row) => row.table_name as string);
  }

  /**
   * Row count and a digest of every row, per table. `realms` is digested
   * without the two columns 0025 adds, so the comparison asks whether every
   * value that existed before is still there.
   */
  async function contents(tables: readonly string[]): Promise<Record<string, unknown>> {
    const result: Record<string, unknown> = {};
    for (const table of tables) {
      const row = table === 'realms' ? `to_jsonb(t) - 'issuer' - 'is_operator'` : 'to_jsonb(t)';
      const { rows } = await db().query(
        `SELECT count(*)::int AS rows,
                md5(coalesce(string_agg((${row})::text, '|' ORDER BY (${row})::text), ''))
                  AS digest
           FROM "${table}" t`
      );
      result[table] = rows[0];
    }
    return result;
  }

  async function appliedMigrations(): Promise<number> {
    const { rows } = await db().query(
      `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`
    );
    return rows[0].n as number;
  }

  async function newRealmColumns(): Promise<{ issuer: string | null; is_operator: boolean }[]> {
    const { rows } = await db().query(`SELECT issuer, is_operator FROM realms ORDER BY name`);
    return rows;
  }

  it('applies to a database at 0024 with data, and changes no existing row', async () => {
    await applyQauthMigrations(connectionString(), folder('before0025'));
    await seedEveryTable();
    const tablesBefore = await publicTables();
    const before = await contents(tablesBefore);
    // Every table that exists before 0025 holds a row, so "unchanged" below
    // is checked against real data, not empty tables.
    expect(Object.values(before).every((table) => (table as { rows: number }).rows > 0)).toBe(true);

    await applyQauthMigrations(connectionString());

    expect(await appliedMigrations()).toBe(MIGRATION_IDX + 1);
    expect(await publicTables()).toEqual([...tablesBefore, 'realm_hosts'].sort());
    expect(await contents(tablesBefore)).toEqual(before);
    expect(await newRealmColumns()).toEqual([
      { issuer: null, is_operator: false },
      { issuer: null, is_operator: false },
    ]);
    expect(await contents(['realm_hosts'])).toEqual({
      realm_hosts: { rows: 0, digest: expect.any(String) },
    });
  });

  it('applies to a database that holds the 0020 schema with data', async () => {
    await applyQauthMigrations(connectionString(), folder('atIssueBaseline'));
    expect(await appliedMigrations()).toBe(ISSUE_BASELINE_IDX + 1);
    expect(await tableExists('realm_keys')).toBe(false);
    await seedEveryTable();
    const tablesBefore = await publicTables();
    const counts = Object.fromEntries(
      Object.entries(await contents(tablesBefore)).map(([table, value]) => [
        table,
        (value as { rows: number }).rows,
      ])
    );
    const { rows: realmsBefore } = await db().query(
      `SELECT id, name, enabled, created_at FROM realms ORDER BY name`
    );

    await applyQauthMigrations(connectionString());

    expect(await appliedMigrations()).toBe(MIGRATION_IDX + 1);
    // 0021–0024 add columns and backfill some of them, so this run checks that
    // no row is lost or added and that the realms are the same realms.
    const after = await contents(tablesBefore);
    for (const [table, rows] of Object.entries(counts)) {
      expect((after[table] as { rows: number }).rows, table).toBe(rows);
    }
    const { rows: realmsAfter } = await db().query(
      `SELECT id, name, enabled, created_at FROM realms ORDER BY name`
    );
    expect(realmsAfter).toEqual(realmsBefore);
    expect(await newRealmColumns()).toEqual([
      { issuer: null, is_operator: false },
      { issuer: null, is_operator: false },
    ]);
    expect(await publicTables()).toEqual(
      [...tablesBefore, 'realm_hosts', 'realm_keys', 'realm_public_keys'].sort()
    );
  });

  it('lets an existing realm take its issuer and primary host once after the upgrade', async () => {
    await applyQauthMigrations(connectionString(), folder('before0025'));
    const [realmId, secondRealmId] = await seedEveryTable();
    await applyQauthMigrations(connectionString());

    // What the boot step (#484) will do for the default realm.
    await db().query(
      `UPDATE realms SET issuer = 'https://auth.example.com', is_operator = true WHERE id = $1`,
      [realmId]
    );
    await db().query(
      `INSERT INTO realm_hosts (host, realm_id, kind)
       VALUES ('auth.example.com', $1, 'primary'), ('auth-server', $1, 'endpoint')`,
      [realmId]
    );

    const { rows } = await db().query(
      `SELECT r.name, r.issuer, r.is_operator, h.kind,
              (SELECT count(*)::int FROM users u WHERE u.realm_id = r.id) AS users,
              (SELECT count(*)::int FROM oauth_clients c WHERE c.realm_id = r.id) AS clients
         FROM realm_hosts h JOIN realms r ON r.id = h.realm_id
        WHERE h.host = 'auth.example.com'`
    );
    expect(rows).toEqual([
      {
        name: 'm0025',
        issuer: 'https://auth.example.com',
        is_operator: true,
        kind: 'primary',
        users: 1,
        clients: 1,
      },
    ]);

    // From here on both are permanent, and the second realm cannot also be
    // the operator realm.
    await expect(
      db().query(`UPDATE realms SET issuer = 'https://other.example.com' WHERE id = $1`, [realmId])
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_issuer_permanent' });
    await expect(
      db().query(
        `UPDATE realm_hosts SET host = 'other.example.com' WHERE realm_id = $1 AND kind = 'primary'`,
        [realmId]
      )
    ).rejects.toMatchObject({ code: '23514', constraint: 'realm_hosts_primary_permanent' });
    await expect(
      db().query(`UPDATE realms SET is_operator = true WHERE id = $1`, [secondRealmId])
    ).rejects.toMatchObject({ code: '23505', constraint: 'idx_realms_one_operator' });
  });
});
