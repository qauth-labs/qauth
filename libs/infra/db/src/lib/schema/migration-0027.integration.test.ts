/**
 * Seed-then-migrate test for migration 0027: the ID-JAG targets column on
 * `oauth_clients` (ADR-011, #434).
 *
 * The migration copies nothing from `audience`. A copy would carry every
 * `client_credentials` audience over as an ID-JAG target, which is the coupling
 * the column exists to remove; ID-JAG is off by default and new, so an operator
 * lists the targets in the seed manifest instead. This test pins that choice:
 * an existing client with an audience reaches no ID-JAG target after the
 * upgrade, and keeps its audience.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * (DROP SCHEMA CASCADE) and upgraded only through 0026, then 0027, so a later
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
const MIGRATION_IDX = 27;

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

describe('migration 0027 — oauth_clients.id_jag_targets (seed-then-migrate)', () => {
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

  /** A pre-0027 `oauth_clients` row with the given audience. */
  async function seedClient(clientId: string, audience: string[] | null): Promise<string> {
    const { rows: realms } = await db().query(
      `INSERT INTO realms (name) VALUES ($1) RETURNING id`,
      [`m0027-${clientId}`]
    );
    const { rows } = await db().query(
      `INSERT INTO oauth_clients
         (realm_id, client_id, client_secret_hash, name, redirect_uris, grant_types, audience)
       VALUES ($1, $2, 'h', $2, '[]'::jsonb, $3::jsonb, $4::jsonb)
       RETURNING id`,
      [
        realms[0].id,
        clientId,
        JSON.stringify(['urn:ietf:params:oauth:grant-type:token-exchange']),
        audience === null ? null : JSON.stringify(audience),
      ]
    );
    return rows[0].id as string;
  }

  async function readClient(
    id: string
  ): Promise<{ audience: string[] | null; id_jag_targets: string[] }> {
    const { rows } = await db().query(
      `SELECT audience, id_jag_targets FROM oauth_clients WHERE id = $1`,
      [id]
    );
    return rows[0];
  }

  it('copies nothing from audience: an existing client reaches no ID-JAG target', async () => {
    const withAudience = await seedClient('with-audience', [
      'https://as.partner.example',
      'https://mcp.partner.example/mcp',
    ]);
    const withoutAudience = await seedClient('without-audience', null);

    await migrate();

    expect(await readClient(withAudience)).toEqual({
      audience: ['https://as.partner.example', 'https://mcp.partner.example/mcp'],
      id_jag_targets: [],
    });
    expect(await readClient(withoutAudience)).toEqual({ audience: null, id_jag_targets: [] });
  });

  it('gives a new row an empty list and refuses anything but an array', async () => {
    await migrate();
    const id = await seedClient('after-upgrade', null);
    expect((await readClient(id)).id_jag_targets).toEqual([]);

    await expect(
      db().query(`UPDATE oauth_clients SET id_jag_targets = '"https://as.partner.example"'`)
    ).rejects.toThrow(/oauth_clients_id_jag_targets_is_array/);
    await expect(db().query(`UPDATE oauth_clients SET id_jag_targets = NULL`)).rejects.toThrow(
      /null value/
    );
  });
});
