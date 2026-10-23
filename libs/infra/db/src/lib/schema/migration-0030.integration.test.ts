/**
 * Seed-then-migrate test for migration 0030: the `sessions` table reshaped
 * for browser sessions, and `session_clients` (ADR-019 Decision 3, issue
 * #468).
 *
 * 0030 empties `sessions` before it reshapes it: no code ever wrote the table,
 * and a row in the old shape models a token session with no authentication
 * time. So the risk is the upgrade itself: a database at 0029 with data in
 * every table, old-shape session rows included, must take 0030 through the
 * same drizzle migrator the migration runner uses, lose nothing but those
 * session rows, and come out with the new columns, constraints and indexes.
 *
 * Requires Docker; self-skips without it. Each case rebuilds the schema from
 * scratch (DROP SCHEMA CASCADE) inside one shared container, and upgrades to
 * 0030 itself, not to the newest migration, so a later migration cannot change
 * what this suite pins.
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

const MIGRATION_IDX = 30;

/**
 * Tables the seed leaves empty. A trigger accepts an `admin_audit_log` row
 * only as the next link of its realm's hash chain (migration 0026), which is
 * the repository's job, and 0030 does not touch either table.
 */
const UNSEEDED = ['admin_audit_log', 'admin_audit_log_checkpoints'];

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

describe('migration 0030 — browser sessions (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;
  let before0030: string | undefined;
  let through0030: string | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    pool = new Pool({ connectionString: container.connectionString, max: 2 });
    before0030 = migrationsFolderBefore(MIGRATION_IDX);
    through0030 = migrationsFolderBefore(MIGRATION_IDX + 1);
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
    for (const folder of [before0030, through0030]) {
      if (folder) rmSync(folder, { recursive: true, force: true });
    }
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool || !container || !before0030 || !through0030) {
      testCtx.skip();
      return;
    }
    await pool.query(
      'DROP SCHEMA IF EXISTS drizzle CASCADE; DROP SCHEMA public CASCADE; CREATE SCHEMA public;'
    );
    await applyQauthMigrations(container.connectionString, before0030);
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  async function upgrade(): Promise<void> {
    if (!container || !through0030) throw new Error('no container');
    await applyQauthMigrations(container.connectionString, through0030);
  }

  async function one(statement: string, params: unknown[] = []): Promise<string> {
    const { rows } = await db().query(statement, params);
    return rows[0].id as string;
  }

  interface Seeded {
    realmId: string;
    otherRealmId: string;
    userId: string;
    clientId: string;
  }

  /**
   * One row in every table the schema has at 0029 but the admin audit tables,
   * two realms, and two old-shape session rows: one live, one revoked.
   */
  async function seedEveryTable(): Promise<Seeded> {
    const realmId = await one(`INSERT INTO realms (name) VALUES ('m0030') RETURNING id`);
    const otherRealmId = await one(
      `INSERT INTO realms (name, enabled) VALUES ('m0030-other', false) RETURNING id`
    );
    await db().query(
      `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ('auth.example.com', $1, 'primary')`,
      [realmId]
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
       VALUES ($1, 'm0030-client', 'h', 'm0030', '["https://app.example.com/cb"]')
       RETURNING id`,
      [realmId]
    );
    await db().query(
      `INSERT INTO api_keys (realm_id, client_id, name, key_hash, prefix, last4)
       VALUES ($1, $2, 'key', 'h', 'qk_m0030', 'abcd')`,
      [realmId, clientId]
    );
    await db().query(
      `INSERT INTO oauth_consents (user_id, oauth_client_id, realm_id) VALUES ($1, $2, $3)`,
      [userId, clientId, realmId]
    );
    await db().query(
      `INSERT INTO authorization_codes
         (code, oauth_client_id, user_id, redirect_uri, code_challenge, expires_at)
       VALUES ('m0030-code', $1, $2, 'https://app.example.com/cb', 'challenge', $3)`,
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
      `INSERT INTO roles (realm_id, name) VALUES ($1, 'm0030') RETURNING id`,
      [realmId]
    );
    await db().query(`INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)`, [userId, roleId]);
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
    await db().query(
      `INSERT INTO events (id, realm_id, category, type, time, data, schema_version)
       VALUES ('0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01', $1, 'user', 'm0030', $2, '{}', 1)`,
      [realmId, Date.now()]
    );
    await db().query(
      `INSERT INTO sessions
         (user_id, oauth_client_id, access_token_hash, refresh_token_hash, expires_at)
       VALUES ($1, $2, 'a', 'r', $3)`,
      [userId, clientId, Date.now() + 60_000]
    );
    await db().query(
      `INSERT INTO sessions (user_id, expires_at, revoked, revoked_at) VALUES ($1, $2, true, $3)`,
      [userId, Date.now() + 60_000, Date.now()]
    );
    return { realmId, otherRealmId, userId, clientId };
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

  async function columns(table: string): Promise<string[]> {
    const { rows } = await db().query(
      `SELECT column_name FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = $1
        ORDER BY column_name`,
      [table]
    );
    return rows.map((row) => row.column_name as string);
  }

  async function indexes(table: string): Promise<string[]> {
    const { rows } = await db().query(
      `SELECT indexname FROM pg_indexes WHERE schemaname = 'public' AND tablename = $1
        ORDER BY indexname`,
      [table]
    );
    return rows.map((row) => row.indexname as string);
  }

  /** Named constraints, without the NOT NULL ones Postgres 18 also lists. */
  async function constraints(table: string): Promise<string[]> {
    const { rows } = await db().query(
      `SELECT conname FROM pg_constraint
        WHERE conrelid = $1::regclass AND contype <> 'n'
        ORDER BY conname`,
      [`public.${table}`]
    );
    return rows.map((row) => row.conname as string);
  }

  it('applies to a database at 0029 with data, and changes no row outside sessions', async () => {
    await seedEveryTable();
    const tablesBefore = await publicTables();
    const kept = tablesBefore.filter((table) => table !== 'sessions');
    const before = await contents(kept);
    // Every table but the admin audit ones holds a row, so "unchanged" below
    // is checked against real data, not empty tables.
    for (const table of kept.filter((t) => !UNSEEDED.includes(t))) {
      expect((before[table] as { rows: number }).rows, table).toBeGreaterThan(0);
    }
    expect(await contents(['sessions'])).toMatchObject({ sessions: { rows: 2 } });

    await upgrade();

    const { rows: applied } = await db().query(
      `SELECT count(*)::int AS n FROM drizzle.__drizzle_migrations`
    );
    expect(applied[0].n).toBe(MIGRATION_IDX + 1);
    expect(await publicTables()).toEqual([...tablesBefore, 'session_clients'].sort());
    expect(await contents(kept)).toEqual(before);
    expect(await contents(['sessions'])).toMatchObject({ sessions: { rows: 0 } });
  });

  it('gives sessions the browser-session shape and adds session_clients', async () => {
    await upgrade();

    expect(await columns('sessions')).toEqual([
      'amr',
      'assurance_level',
      'auth_time',
      'created_at',
      'expires_at',
      'id',
      'ip_address',
      'last_seen_at',
      'realm_id',
      'revoked_at',
      'revoked_reason',
      'user_agent',
      'user_id',
    ]);
    expect(await indexes('sessions')).toEqual([
      'idx_sessions_expires_at',
      'idx_sessions_realm_user_active',
      'idx_sessions_user_id',
      'sessions_pkey',
    ]);
    expect(await constraints('sessions')).toEqual([
      'sessions_amr_is_array',
      'sessions_assurance_level_valid',
      'sessions_pkey',
      'sessions_realm_id_realms_id_fk',
      'sessions_revoked_pair',
      'sessions_revoked_reason_valid',
      'sessions_user_realm_fk',
    ]);
    expect(await columns('session_clients')).toEqual([
      'first_seen_at',
      'oauth_client_id',
      'session_id',
    ]);
    expect(await indexes('session_clients')).toEqual([
      'idx_session_clients_oauth_client_id',
      'session_clients_pk',
    ]);
    expect(await constraints('users')).toContain('users_id_realm_id_unique');
  });

  it('lets an existing user take a browser session after the upgrade, in the user realm only', async () => {
    const { realmId, otherRealmId, userId, clientId } = await seedEveryTable();
    await upgrade();

    const sessionId = await one(
      `INSERT INTO sessions (realm_id, user_id, auth_time, amr, expires_at)
       VALUES ($1, $2, $3, '["pwd"]', $4) RETURNING id`,
      [realmId, userId, Date.now(), Date.now() + 60_000]
    );
    await db().query(`INSERT INTO session_clients (session_id, oauth_client_id) VALUES ($1, $2)`, [
      sessionId,
      clientId,
    ]);

    await expect(
      db().query(
        `INSERT INTO sessions (realm_id, user_id, auth_time, expires_at) VALUES ($1, $2, 1, 2)`,
        [otherRealmId, userId]
      )
    ).rejects.toMatchObject({ code: '23503', constraint: 'sessions_user_realm_fk' });
  });
});
