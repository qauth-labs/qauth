/**
 * Seed-then-migrate test for migration 0036: event retention (#536).
 *
 * A realm created before the migration gets the default retention, 90 days
 * of user events and 365 of admin events, and from then on no writer can
 * keep admin events fewer than 90 days: the CHECK refuses it for every role,
 * as `eventRetentionProblems` does in the application.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0035, then 0036, so a later migration cannot change
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

const MIGRATION_IDX = 36;

describe('migration 0036 — event retention (seed-then-migrate)', () => {
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

  it('gives a realm created before it 90 days of user events and 365 of admin events', async () => {
    const {
      rows: [seeded],
    } = await db().query<{ id: string }>(
      `INSERT INTO realms (name, issuer) VALUES ('old', 'https://old.example.com') RETURNING id`
    );
    await migrate();

    const { rows } = await db().query(
      'SELECT user_event_retention_days, admin_event_retention_days FROM realms WHERE id = $1',
      [seeded.id]
    );
    expect(rows).toEqual([{ user_event_retention_days: 90, admin_event_retention_days: 365 }]);
  });

  it('refuses admin events kept 89 days and accepts 90, for every writer', async () => {
    await migrate();
    const {
      rows: [realm],
    } = await db().query<{ id: string }>(`INSERT INTO realms (name) VALUES ('r') RETURNING id`);

    await expect(
      db().query('UPDATE realms SET admin_event_retention_days = 89 WHERE id = $1', [realm.id])
    ).rejects.toMatchObject({
      code: '23514',
      constraint: 'realms_admin_event_retention_days_range',
    });
    await db().query('UPDATE realms SET admin_event_retention_days = 90 WHERE id = $1', [realm.id]);

    await expect(
      db().query(`INSERT INTO realms (name, user_event_retention_days) VALUES ('zero', 0)`)
    ).rejects.toMatchObject({
      code: '23514',
      constraint: 'realms_user_event_retention_days_range',
    });
    await expect(
      db().query(`INSERT INTO realms (name, admin_event_retention_days) VALUES ('long', 36501)`)
    ).rejects.toMatchObject({
      code: '23514',
      constraint: 'realms_admin_event_retention_days_range',
    });
  });

  it('keeps one anchor per realm, a seq and a SHA-256 hash', async () => {
    await migrate();
    const realmId = '0192e000-0000-7000-8000-000000000001';
    await db().query(
      `INSERT INTO event_chain_anchors (realm_id, seq, hash) VALUES ($1, 5, decode(repeat('ab', 32), 'hex'))`,
      [realmId]
    );
    await expect(
      db().query(
        `INSERT INTO event_chain_anchors (realm_id, seq, hash) VALUES ($1, 6, decode(repeat('ab', 32), 'hex'))`,
        [realmId]
      )
    ).rejects.toMatchObject({ code: '23505' });
    await expect(
      db().query(
        `INSERT INTO event_chain_anchors (realm_id, seq, hash) VALUES (gen_random_uuid(), 0, decode(repeat('ab', 32), 'hex'))`
      )
    ).rejects.toMatchObject({ code: '23514', constraint: 'event_chain_anchors_seq_positive' });
    await expect(
      db().query(
        `INSERT INTO event_chain_anchors (realm_id, seq, hash) VALUES (gen_random_uuid(), 1, decode('ab', 'hex'))`
      )
    ).rejects.toMatchObject({ code: '23514', constraint: 'event_chain_anchors_hash_sha256' });
  });

  it('replaces the time index with the retention index', async () => {
    await migrate();
    const { rows } = await db().query<{ indexname: string; indexdef: string }>(
      `SELECT indexname, indexdef FROM pg_indexes
       WHERE tablename = 'events' AND indexname IN ('idx_events_time', 'idx_events_retention')`
    );
    expect(rows).toEqual([
      {
        indexname: 'idx_events_retention',
        indexdef:
          'CREATE INDEX idx_events_retention ON public.events USING btree (realm_id, category, "time")',
      },
    ]);
  });
});
