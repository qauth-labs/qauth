/**
 * Seed-then-migrate test for migration 0034: the passkey RP ID lock moves to
 * `realms.webauthn_rp_id_locked_at` (ADR-019 Decision 2, #553).
 *
 * Under migration 0028 (#467) a non-NULL `webauthn_rp_id` was the lock, written
 * by the first enrolment. After the upgrade such a realm must still be locked
 * under the same RP ID, at the time of its first passkey; a realm with no
 * passkey must be unlocked, and free to change its RP ID, which 0028's
 * trigger forbade once the column was set.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * (DROP SCHEMA CASCADE) and upgraded only through 0033, then 0034, so a later
 * migration cannot change what this test sees.
 */
import { readFileSync } from 'node:fs';
import path from 'node:path';

import {
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
} from '@qauth-labs/shared-testing';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const DRIZZLE_DIR = path.resolve(process.cwd(), 'libs/infra/db/drizzle');
const MIGRATION_IDX = 34;

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

/** Apply one migration file in a single transaction, as the drizzle migrator does. */
async function applyMigrationFile(pool: Pool, file: string): Promise<void> {
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

describe('migration 0034 — realms.webauthn_rp_id_locked_at (seed-then-migrate)', () => {
  let container: StartedPostgres | undefined;
  let pool: Pool | undefined;
  let dockerUp = false;

  const files = migrationFiles();
  const target = files.find((f) => f.idx === MIGRATION_IDX)?.file;
  const preFiles = files.filter((f) => f.idx < MIGRATION_IDX).map((f) => f.file);

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
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
    await pool.query('DROP SCHEMA public CASCADE; CREATE SCHEMA public;');
    for (const file of preFiles) {
      await applyMigrationFile(pool, file);
    }
  });

  function db(): Pool {
    if (!pool) throw new Error('no pool');
    return pool;
  }

  async function migrate(): Promise<void> {
    if (!target) throw new Error(`migration ${MIGRATION_IDX} is not in the journal`);
    await applyMigrationFile(db(), target);
  }

  /** A pre-0034 realm, its RP ID as 0028 stored it, and `updated_at`. */
  async function seedRealm(name: string, rpId: string | null, updatedAt: number): Promise<string> {
    const { rows } = await db().query(
      `INSERT INTO realms (name, issuer, webauthn_rp_id, updated_at)
       VALUES ($1, $2, $3, $4) RETURNING id`,
      [name, `https://${name}.example.com`, rpId, updatedAt]
    );
    return rows[0].id as string;
  }

  async function seedCredential(
    realmId: string,
    providerType: string,
    externalSub: string,
    createdAt: number
  ): Promise<void> {
    const { rows } = await db().query(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [
      realmId,
    ]);
    await db().query(
      `INSERT INTO user_credentials (user_id, realm_id, provider_type, external_sub, created_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [rows[0].id, realmId, providerType, externalSub, createdAt]
    );
  }

  async function readRealm(
    id: string
  ): Promise<{ webauthn_rp_id: string | null; webauthn_rp_id_locked_at: string | null }> {
    const { rows } = await db().query(
      `SELECT webauthn_rp_id, webauthn_rp_id_locked_at FROM realms WHERE id = $1`,
      [id]
    );
    return rows[0];
  }

  it('keeps a realm 0028 locked locked, under the same RP ID, at its first passkey', async () => {
    const parent = await seedRealm('parent', 'example.com', 1_700_000_000_500);
    await seedCredential(parent, 'webauthn', 'c2Vjb25k', 1_700_000_000_300);
    await seedCredential(parent, 'webauthn', 'Zmlyc3Q', 1_700_000_000_100);
    await seedCredential(parent, 'password', 'ada@example.com', 1_600_000_000_000);
    const host = await seedRealm('host', 'host.example.com', 1_700_000_000_900);
    await seedCredential(host, 'webauthn', 'aG9zdA', 1_700_000_000_200);

    await migrate();

    expect(await readRealm(parent)).toEqual({
      webauthn_rp_id: 'example.com',
      webauthn_rp_id_locked_at: '1700000000100',
    });
    expect(await readRealm(host)).toEqual({
      webauthn_rp_id: 'host.example.com',
      webauthn_rp_id_locked_at: '1700000000200',
    });
    await expect(
      db().query(`UPDATE realms SET webauthn_rp_id = NULL WHERE id = $1`, [parent])
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_webauthn_rp_id_locked' });
  });

  it('locks a realm whose stored RP ID outlived its passkeys at its last update', async () => {
    const realm = await seedRealm('orphan', 'orphan.example.com', 1_700_000_000_700);

    await migrate();

    expect(await readRealm(realm)).toEqual({
      webauthn_rp_id: 'orphan.example.com',
      webauthn_rp_id_locked_at: '1700000000700',
    });
  });

  it('locks a realm that has a passkey but no stored RP ID, under its host', async () => {
    const realm = await seedRealm('bare', null, 1_700_000_000_800);
    await seedCredential(realm, 'webauthn', 'YmFyZQ', 1_700_000_000_400);

    await migrate();

    expect(await readRealm(realm)).toEqual({
      webauthn_rp_id: null,
      webauthn_rp_id_locked_at: '1700000000400',
    });
  });

  it('leaves a realm with no passkey unlocked, and lets its RP ID change, which 0028 forbade', async () => {
    const realm = await seedRealm('fresh', null, 1_700_000_000_000);
    await seedCredential(realm, 'password', 'grace@example.com', 1_700_000_000_000);

    await migrate();

    expect(await readRealm(realm)).toEqual({
      webauthn_rp_id: null,
      webauthn_rp_id_locked_at: null,
    });
    await db().query(`UPDATE realms SET webauthn_rp_id = 'example.com' WHERE id = $1`, [realm]);
    await db().query(`UPDATE realms SET webauthn_rp_id = NULL WHERE id = $1`, [realm]);
    expect((await readRealm(realm)).webauthn_rp_id).toBeNull();
  });

  it("drops 0028's trigger and function, and adds the lock trigger", async () => {
    await migrate();

    const { rows: triggers } = await db().query<{ tgname: string }>(
      `SELECT tgname FROM pg_trigger WHERE tgrelid = 'realms'::regclass AND NOT tgisinternal
       ORDER BY tgname`
    );
    expect(triggers.map((row) => row.tgname)).toContain('realms_webauthn_rp_id_locked');
    expect(triggers.map((row) => row.tgname)).not.toContain('realms_webauthn_rp_id_permanent');
    const { rows: functions } = await db().query<{ proname: string }>(
      `SELECT proname FROM pg_proc WHERE proname LIKE 'realms_webauthn_rp_id_%' ORDER BY proname`
    );
    expect(functions.map((row) => row.proname)).toEqual(['realms_webauthn_rp_id_locked']);
  });
});
