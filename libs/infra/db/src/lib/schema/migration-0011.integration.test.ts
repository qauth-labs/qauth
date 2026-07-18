/**
 * Seed-then-migrate tests for migration 0011 (#230): the ADR-002 point of no
 * return — drops users.email/email_normalized/password_hash, promotes
 * email_verification_tokens.credential_id to NOT NULL, and drops user_id.
 *
 * Three properties are load-bearing and only provable against real Postgres:
 *   A. GUARD-ABORT ATOMICITY — incomplete backfill aborts the migration with
 *      the remediation message and applies ZERO DDL (transactional no-op).
 *   B. BACKFILL RESCUE — in-flight tokens minted without credential_id by a
 *      straggling pre-#228 writer are re-pointed, not killed, when their user
 *      has a credential.
 *   C. DROPS + SUB STABILITY — orphaned tokens deleted, columns/indexes gone,
 *      NOT NULL enforced, and users.id survives unchanged (epic #224 AC).
 *
 * Requires Docker; self-skips without it. Each case rebuilds the schema from
 * scratch (DROP SCHEMA CASCADE) inside one shared container.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  isDockerAvailable,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(process.cwd(), 'libs/infra/db/drizzle');

interface JournalEntry {
  idx: number;
  tag: string;
}

function migrationFiles(): { idx: number; file: string }[] {
  const journal = JSON.parse(
    readFileSync(path.join(DRIZZLE_DIR, 'meta/_journal.json'), 'utf8')
  ) as { entries: JournalEntry[] };
  return journal.entries
    .sort((a, b) => a.idx - b.idx)
    .map((e) => ({ idx: e.idx, file: path.join(DRIZZLE_DIR, `${e.tag}.sql`) }));
}

async function applyMigrationFile(pool: Pool, file: string): Promise<void> {
  const statements = readFileSync(file, 'utf8')
    .split('--> statement-breakpoint')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  for (const statement of statements) {
    await pool.query(statement);
  }
}

/** Apply 0011 atomically, the way the drizzle migrator does (one transaction). */
async function apply0011Transactionally(pool: Pool, file: string): Promise<void> {
  const statements = readFileSync(file, 'utf8')
    .split('--> statement-breakpoint')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    for (const statement of statements) {
      await client.query(statement);
    }
    await client.query('COMMIT');
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

describe('migration 0011 — legacy column drop (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;

  const files = migrationFiles();
  const file0011 = files.find((f) => f.idx === 11)?.file;
  // STRICTLY idx < 11: the pre-set is the post-#229, pre-drop schema.
  const preFiles = files.filter((f) => f.idx < 11).map((f) => f.file);

  beforeAll(async () => {
    dockerUp = await isDockerAvailable();
    if (!dockerUp) return;
    container = await startPostgresContainer();
    pool = new Pool({ connectionString: container.connectionString, max: 2 });
  }, 180_000);

  afterAll(async () => {
    await pool?.end();
    await container?.stop();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !pool) {
      testCtx.skip();
      return;
    }
    // Fresh schema per case — guard-abort and success paths cannot share state.
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    for (const file of preFiles) {
      await applyMigrationFile(pool, file);
    }
  });

  async function seedRealm(): Promise<string> {
    if (!pool) throw new Error('no pool');
    const { rows } = await pool.query(`INSERT INTO realms (name) VALUES ('m0011') RETURNING id`);
    return rows[0].id as string;
  }

  async function seedLegacyUser(realmId: string, email: string): Promise<string> {
    if (!pool) throw new Error('no pool');
    const { rows } = await pool.query(
      `INSERT INTO users (realm_id, email, email_normalized, password_hash, email_verified)
       VALUES ($1, $2, $2, '$argon2id$fake', false) RETURNING id`,
      [realmId, email]
    );
    return rows[0].id as string;
  }

  async function seedCredential(
    realmId: string,
    userId: string,
    email: string,
    providerType = 'password'
  ): Promise<string> {
    if (!pool) throw new Error('no pool');
    const { rows } = await pool.query(
      `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub, credential_data)
       VALUES ($1, $2, $4, $3, '{"password_hash":"$argon2id$fake","email_verified":false}'::jsonb)
       RETURNING id`,
      [userId, realmId, email, providerType]
    );
    return rows[0].id as string;
  }

  async function seedLegacyToken(userId: string, hash: string): Promise<string> {
    if (!pool) throw new Error('no pool');
    // Pre-#228-writer shape: user_id only, credential_id NULL.
    const { rows } = await pool.query(
      `INSERT INTO email_verification_tokens (token_hash, user_id, expires_at)
       VALUES ($1, $2, $3) RETURNING id`,
      [hash, userId, Date.now() + 3_600_000]
    );
    return rows[0].id as string;
  }

  async function userColumns(): Promise<string[]> {
    if (!pool) throw new Error('no pool');
    const { rows } = await pool.query(
      `SELECT column_name FROM information_schema.columns WHERE table_name = 'users'`
    );
    return rows.map((r) => r.column_name as string);
  }

  it('CASE A: aborts atomically with remediation when a user lacks credential coverage', async () => {
    if (!pool || !file0011) throw new Error('no pool/0011');
    const realmId = await seedRealm();
    // Legacy-only user: password_hash present, NO credential row (#226 never
    // ran for them) — exactly the data-loss case the guard exists for.
    await seedLegacyUser(realmId, 'stranded@example.com');

    await expect(apply0011Transactionally(pool, file0011)).rejects.toThrow(
      /QAuth migration 0011 aborted.*backfill runbook/s
    );

    // ATOMICITY: zero DDL applied — the legacy columns and tokens.user_id all
    // still exist, so the aborted deploy leaves a fully functional database.
    const cols = await userColumns();
    expect(cols).toEqual(expect.arrayContaining(['email', 'email_normalized', 'password_hash']));
    const { rows } = await pool.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name = 'email_verification_tokens' AND column_name = 'user_id'`
    );
    expect(rows).toHaveLength(1);
  });

  it('CASE D: aborts when a user has ONLY a non-password credential (hash survives only in the dropped column)', async () => {
    if (!pool || !file0011) throw new Error('no pool/0011');
    const realmId = await seedRealm();
    // Guard clause 1's specific target: password_hash IS NOT NULL but the
    // only credential row is non-password — clause 2 (any credential) passes,
    // so ONLY the provider_type='password' scoping in clause 1 saves the hash.
    const userId = await seedLegacyUser(realmId, 'oidc-only@example.com');
    await seedCredential(realmId, userId, 'oidc-only@example.com', 'oidc_test');

    await expect(apply0011Transactionally(pool, file0011)).rejects.toThrow(
      /QAuth migration 0011 aborted.*backfill runbook/s
    );
    const cols = await userColumns();
    expect(cols).toEqual(expect.arrayContaining(['password_hash']));
  });

  it('CASE B: rescues in-flight NULL-credential_id tokens whose user has a credential', async () => {
    if (!pool || !file0011) throw new Error('no pool/0011');
    const realmId = await seedRealm();
    const userId = await seedLegacyUser(realmId, 'covered@example.com');
    const credId = await seedCredential(realmId, userId, 'covered@example.com');
    const tokenId = await seedLegacyToken(userId, 'a'.repeat(64));

    await apply0011Transactionally(pool, file0011);

    const { rows } = await pool.query(
      `SELECT credential_id FROM email_verification_tokens WHERE id = $1`,
      [tokenId]
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].credential_id).toBe(credId);
  });

  it('CASE C: drops columns and user_id, enforces NOT NULL, keeps sub stable', async () => {
    if (!pool || !file0011) throw new Error('no pool/0011');
    const realmId = await seedRealm();
    const coveredUser = await seedLegacyUser(realmId, 'ok@example.com');
    const credId = await seedCredential(realmId, coveredUser, 'ok@example.com');
    const keptToken = await seedLegacyToken(coveredUser, 'b'.repeat(64));
    // NOTE: no orphaned-token case exists against the real pre-0011 schema —
    // every user has password_hash NOT NULL, so the guard demands a password
    // credential for everyone and the rescue UPDATE always resolves. The
    // migration's DELETE is defense-in-depth against constraint-violating
    // data only, deliberately untested against unreachable states.

    await apply0011Transactionally(pool, file0011);

    // The rescued token survives with its credential link.
    const { rows: tokens } = await pool.query(
      `SELECT id, credential_id FROM email_verification_tokens`
    );
    expect(tokens.map((t) => t.id)).toEqual([keptToken]);
    expect(tokens[0].credential_id).toBe(credId);

    // Columns gone; NOT NULL enforced; user_id gone.
    const cols = await userColumns();
    expect(cols).not.toEqual(expect.arrayContaining(['email']));
    expect(cols).not.toEqual(expect.arrayContaining(['email_normalized']));
    expect(cols).not.toEqual(expect.arrayContaining(['password_hash']));
    const { rows: tokenCols } = await pool.query(
      `SELECT column_name, is_nullable FROM information_schema.columns
       WHERE table_name = 'email_verification_tokens' AND column_name IN ('credential_id','user_id')`
    );
    expect(tokenCols).toEqual([{ column_name: 'credential_id', is_nullable: 'NO' }]);

    // Dropped-column indexes are gone with them.
    const { rows: indexes } = await pool.query(
      `SELECT indexname FROM pg_indexes WHERE tablename = 'users'`
    );
    const names = indexes.map((r) => r.indexname as string);
    expect(names).not.toContain('idx_users_realm_email_normalized_unique');
    expect(names).not.toContain('idx_users_email');
    expect(names).not.toContain('idx_users_realm_email_enabled');

    // Epic #224 AC: sub stability — the pre-migration users.id is unchanged.
    const { rows: userRows } = await pool.query(`SELECT id FROM users WHERE id = $1`, [
      coveredUser,
    ]);
    expect(userRows).toHaveLength(1);
    expect(userRows[0].id).toBe(coveredUser);
  });
});
