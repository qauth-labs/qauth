/**
 * Seed-then-migrate test for migration 0010 (#228): email_verification_tokens
 * gains a nullable credential_id FK with an in-file backfill from each user's
 * password credential.
 *
 * Unlike the other integration suites (which apply ALL migrations via
 * setupIntegrationDb), this one applies 0000-0009, seeds pre-#228-shaped data
 * (tokens with only user_id), then applies 0010 and asserts the backfill and
 * the rollback-safety properties: column nullable, user_id untouched,
 * insert-without-credential_id still succeeds, FK cascades.
 *
 * Requires Docker; self-skips without it.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  isDockerAvailable,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(process.cwd(), 'libs/infra/db/drizzle');

interface JournalEntry {
  idx: number;
  tag: string;
}

function migrationFiles(): { idx: number; file: string }[] {
  const journal = JSON.parse(
    readFileSync(path.join(DRIZZLE_DIR, 'meta/_journal.json'), 'utf8')
  ) as {
    entries: JournalEntry[];
  };
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

describe('migration 0010 — email_verification_tokens.credential_id (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;

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

  it('backfills credential_id from password credentials and stays rollback-safe', async (testCtx) => {
    if (!dockerUp || !pool) {
      testCtx.skip();
      return;
    }

    const files = migrationFiles();
    const file0010 = files.find((f) => f.idx === 10)?.file;
    expect(file0010).toBeDefined();
    // STRICTLY idx < 10: later migrations (0011+) must NOT be applied here —
    // this harness seeds and asserts against the historic pre-0010 schema.
    const preFiles = files.filter((f) => f.idx < 10).map((f) => f.file);

    // 1. Apply 0000-0009 — the pre-#228 schema.
    for (const file of preFiles) {
      await applyMigrationFile(pool, file);
    }

    // 2. Seed pre-#228-shaped data: realm, two users, their password
    // credentials (#226 backfill state), one user WITHOUT a credential
    // (registered after the last backfill run), and user_id-only tokens.
    const { rows: realmRows } = await pool.query(
      `INSERT INTO realms (name) VALUES ('migration-test') RETURNING id`
    );
    const realmId = realmRows[0].id as string;

    async function seedUser(email: string): Promise<string> {
      if (!pool) throw new Error('no pool');
      const { rows } = await pool.query(
        `INSERT INTO users (realm_id, email, email_normalized, password_hash, email_verified)
         VALUES ($1, $2, $2, '$argon2id$fake', false) RETURNING id`,
        [realmId, email]
      );
      return rows[0].id as string;
    }
    async function seedCredential(userId: string, email: string): Promise<string> {
      if (!pool) throw new Error('no pool');
      const { rows } = await pool.query(
        `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub, credential_data)
         VALUES ($1, $2, 'password', $3, '{"password_hash":"$argon2id$fake","email_verified":false}'::jsonb)
         RETURNING id`,
        [userId, realmId, email]
      );
      return rows[0].id as string;
    }
    async function seedToken(userId: string, hash: string): Promise<string> {
      if (!pool) throw new Error('no pool');
      const { rows } = await pool.query(
        `INSERT INTO email_verification_tokens (token_hash, user_id, expires_at)
         VALUES ($1, $2, $3) RETURNING id`,
        [hash, userId, Date.now() + 3_600_000]
      );
      return rows[0].id as string;
    }

    const userA = await seedUser('a@example.com');
    const userB = await seedUser('b@example.com');
    const orphanUser = await seedUser('orphan@example.com');
    const credA = await seedCredential(userA, 'a@example.com');
    const credB = await seedCredential(userB, 'b@example.com');
    const tokenA = await seedToken(userA, 'a'.repeat(64));
    const tokenB = await seedToken(userB, 'b'.repeat(64));
    const tokenOrphan = await seedToken(orphanUser, 'c'.repeat(64));

    // 3. Apply 0010.
    if (!file0010) throw new Error('unreachable');
    await applyMigrationFile(pool, file0010);

    // 4. Every token with a password credential is backfilled to it.
    const { rows: after } = await pool.query(
      `SELECT id, user_id, credential_id FROM email_verification_tokens ORDER BY created_at`
    );
    const byId = new Map(after.map((r) => [r.id as string, r]));
    expect(byId.get(tokenA)?.credential_id).toBe(credA);
    expect(byId.get(tokenB)?.credential_id).toBe(credB);
    // No credential to point at → stays NULL (served by the reader fallback).
    expect(byId.get(tokenOrphan)?.credential_id).toBeNull();
    // user_id untouched everywhere.
    expect(byId.get(tokenA)?.user_id).toBe(userA);

    // 5. Rollback safety: the column is nullable and a pre-#228 binary's
    // insert (no credential_id) still succeeds.
    const { rows: colInfo } = await pool.query(
      `SELECT is_nullable FROM information_schema.columns
       WHERE table_name = 'email_verification_tokens' AND column_name = 'credential_id'`
    );
    expect(colInfo[0].is_nullable).toBe('YES');
    await pool.query(
      `INSERT INTO email_verification_tokens (token_hash, user_id, expires_at)
       VALUES ($1, $2, $3)`,
      ['d'.repeat(64), userA, Date.now() + 3_600_000]
    );

    // 6. The FK cascades: deleting a credential removes its tokens.
    await pool.query(`DELETE FROM user_credentials WHERE id = $1`, [credB]);
    const { rows: bTokens } = await pool.query(
      `SELECT id FROM email_verification_tokens WHERE id = $1`,
      [tokenB]
    );
    expect(bTokens).toHaveLength(0);

    // 7. The credential_id index exists.
    const { rows: indexes } = await pool.query(
      `SELECT indexname FROM pg_indexes WHERE tablename = 'email_verification_tokens'`
    );
    expect(indexes.map((r) => r.indexname)).toContain(
      'idx_email_verification_tokens_credential_id'
    );
  }, 120_000);
});
