/**
 * Seed-then-migrate tests for migration 0023: the operator trust marker on
 * `oauth_clients` (ANT-2026-O8U3P920) and the operator-only suspension
 * (ANT-2026-DR5XI3LV).
 *
 * The first backfill decides, from columns the earlier write paths always set,
 * which existing clients an operator provisioned. Getting a self-service client
 * wrong turns it back into an open redirector, so every kind of row the code
 * base can have written is seeded on the pre-0023 schema and checked after.
 * The second carries every existing disable over as a suspension, because the
 * owner may re-enable a client from now on and the row does not say who
 * disabled it.
 *
 * Requires Docker; self-skips without it. Each case rebuilds the schema from
 * scratch (DROP SCHEMA CASCADE) inside the suite's one database.
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
const MIGRATION_IDX = 23;

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

describe('migration 0023 — oauth_clients operator marker (seed-then-migrate)', () => {
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

  async function seedRealm(): Promise<string> {
    const { rows } = await db().query(`INSERT INTO realms (name) VALUES ('m0023') RETURNING id`);
    return rows[0].id as string;
  }

  async function seedUser(realmId: string): Promise<string> {
    const { rows } = await db().query(`INSERT INTO users (realm_id) VALUES ($1) RETURNING id`, [
      realmId,
    ]);
    return rows[0].id as string;
  }

  /** A pre-0023 `oauth_clients` row, shaped by whichever path wrote it. */
  async function seedClient(
    realmId: string,
    clientId: string,
    opts: {
      developerId?: string | null;
      dynamicRegisteredAt?: number | null;
      metadata?: Record<string, unknown> | null;
      redirectUris?: string[];
      enabled?: boolean;
    } = {}
  ): Promise<string> {
    const { rows } = await db().query(
      `INSERT INTO oauth_clients
         (realm_id, client_id, client_secret_hash, name, redirect_uris,
          developer_id, dynamic_registered_at, metadata, enabled)
       VALUES ($1, $2, 'h', $2, $3::jsonb, $4, $5, $6::jsonb, $7)
       RETURNING id`,
      [
        realmId,
        clientId,
        JSON.stringify(opts.redirectUris ?? ['https://app.example.com/cb']),
        opts.developerId ?? null,
        opts.dynamicRegisteredAt ?? null,
        opts.metadata === undefined || opts.metadata === null
          ? null
          : JSON.stringify(opts.metadata),
        opts.enabled ?? true,
      ]
    );
    return rows[0].id as string;
  }

  async function seedClientAudit(oauthClientId: string, event: string): Promise<void> {
    await db().query(
      `INSERT INTO audit_logs (oauth_client_id, event, event_type, success)
       VALUES ($1, $2, 'client', true)`,
      [oauthClientId, event]
    );
  }

  async function marker(clientId: string): Promise<boolean> {
    const { rows } = await db().query(
      `SELECT provisioned_by_operator FROM oauth_clients WHERE client_id = $1`,
      [clientId]
    );
    return rows[0].provisioned_by_operator as boolean;
  }

  it('marks the system client and seed-script clients, and nothing self-service', async () => {
    if (!target) throw new Error('migration 0023 missing from the journal');
    const realmId = await seedRealm();
    const developer = await seedUser(realmId);

    // Operator paths: no owner, no DCR stamp, no metadata.
    await seedClient(realmId, 'system', { redirectUris: [] });
    await seedClient(realmId, 'seeded-confidential');
    // Open DCR (anonymous) and developer-attributed DCR.
    const dcr = await seedClient(realmId, 'dcr-anon', {
      dynamicRegisteredAt: Date.now(),
      metadata: { registrationType: 'dynamic' },
    });
    await seedClientAudit(dcr, 'oauth.client.registered');
    await seedClient(realmId, 'dcr-attributed', {
      developerId: developer,
      dynamicRegisteredAt: Date.now(),
      metadata: { registrationType: 'dynamic' },
    });
    // CIMD materialisation.
    await seedClient(realmId, 'https://app.example.com/client.json', {
      metadata: { registrationType: 'cimd', client_id_metadata_url: 'x' },
    });
    // POST /api/clients — the gap the finding names.
    const owned = await seedClient(realmId, 'api-owned', { developerId: developer });
    await seedClientAudit(owned, 'oauth.client.created');

    await applyMigrationFile(db(), target);

    expect(await marker('system')).toBe(true);
    expect(await marker('seeded-confidential')).toBe(true);
    expect(await marker('dcr-anon')).toBe(false);
    expect(await marker('dcr-attributed')).toBe(false);
    expect(await marker('https://app.example.com/client.json')).toBe(false);
    expect(await marker('api-owned')).toBe(false);
  });

  it('leaves a POST /api/clients client unmarked after its owner row is gone', async () => {
    if (!target) throw new Error('migration 0023 missing from the journal');
    const realmId = await seedRealm();
    const developer = await seedUser(realmId);
    const owned = await seedClient(realmId, 'api-orphan', { developerId: developer });
    await seedClientAudit(owned, 'oauth.client.created');
    // developer_id is ON DELETE SET NULL, so the row now looks ownerless; the
    // client-management audit row is what still says who created it.
    await db().query(`DELETE FROM users WHERE id = $1`, [developer]);
    const { rows } = await db().query(`SELECT developer_id FROM oauth_clients WHERE id = $1`, [
      owned,
    ]);
    expect(rows[0].developer_id).toBeNull();

    await applyMigrationFile(db(), target);

    expect(await marker('api-orphan')).toBe(false);
  });

  it('gives new rows false by default', async () => {
    if (!target) throw new Error('migration 0023 missing from the journal');
    const realmId = await seedRealm();
    await applyMigrationFile(db(), target);

    await seedClient(realmId, 'after-migration');

    expect(await marker('after-migration')).toBe(false);
  });

  async function suspension(
    clientId: string
  ): Promise<{ suspended: boolean; suspendedAt: string | null; enabled: boolean }> {
    const { rows } = await db().query(
      `SELECT suspended, suspended_at, enabled FROM oauth_clients WHERE client_id = $1`,
      [clientId]
    );
    return {
      suspended: rows[0].suspended as boolean,
      suspendedAt: rows[0].suspended_at as string | null,
      enabled: rows[0].enabled as boolean,
    };
  }

  it('suspends every client that is disabled when it runs, and only those', async () => {
    if (!target) throw new Error('migration 0023 missing from the journal');
    const realmId = await seedRealm();
    const developer = await seedUser(realmId);
    // The operator's only switch until now: an UPDATE by hand.
    await seedClient(realmId, 'operator-disabled', { developerId: developer, enabled: false });
    await seedClient(realmId, 'ownerless-disabled', { enabled: false });
    await seedClient(realmId, 'live', { developerId: developer });

    await applyMigrationFile(db(), target);

    const disabled = await suspension('operator-disabled');
    expect(disabled.suspended).toBe(true);
    expect(disabled.suspendedAt).not.toBeNull();
    // `enabled` is left as it was; lifting the suspension later does not
    // re-enable the client by itself.
    expect(disabled.enabled).toBe(false);
    expect((await suspension('ownerless-disabled')).suspended).toBe(true);
    const live = await suspension('live');
    expect(live).toEqual({ suspended: false, suspendedAt: null, enabled: true });
  });

  it('gives new rows suspended = false and no suspended_at', async () => {
    if (!target) throw new Error('migration 0023 missing from the journal');
    const realmId = await seedRealm();
    await applyMigrationFile(db(), target);

    await seedClient(realmId, 'after-migration', { enabled: false });

    expect(await suspension('after-migration')).toEqual({
      suspended: false,
      suspendedAt: null,
      enabled: false,
    });
  });
});
