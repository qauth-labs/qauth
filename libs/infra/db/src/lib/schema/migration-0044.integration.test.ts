/**
 * Seed-then-migrate test for migration 0044: `users.not_valid_before` (#748).
 *
 * The migration applies to a schema that holds accounts, enabled and disabled:
 * every one keeps its row with no time, and an insert without the column, as
 * the previous release makes during a rolling upgrade, still works. From then
 * on disabling an account, by any `UPDATE`, records the time of the change;
 * enabling it again leaves the time as it is, disabling it again moves it
 * forward, and no update moves it back or clears it.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0043, then 0044, so a later migration cannot change
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

const MIGRATION_IDX = 44;

describe('migration 0044 — users.not_valid_before (seed-then-migrate)', () => {
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

  async function seedRealm(): Promise<string> {
    const {
      rows: [realm],
    } = await db().query<{ id: string }>(`INSERT INTO realms (name) VALUES ('r') RETURNING id`);
    return realm.id;
  }

  /** An account as 0043 and the previous release insert it: no `not_valid_before`. */
  async function seedUser(realmId: string, enabled = true): Promise<string> {
    const {
      rows: [user],
    } = await db().query<{ id: string }>(
      `INSERT INTO users (realm_id, enabled) VALUES ($1, $2) RETURNING id`,
      [realmId, enabled]
    );
    return user.id;
  }

  async function notValidBefore(userId: string): Promise<number | null> {
    const { rows } = await db().query<{ not_valid_before: string | null }>(
      `SELECT not_valid_before FROM users WHERE id = $1`,
      [userId]
    );
    const value = rows[0]?.not_valid_before;
    return value === null || value === undefined ? null : Number(value);
  }

  async function setEnabled(userId: string, enabled: boolean): Promise<void> {
    await db().query(`UPDATE users SET enabled = $1 WHERE id = $2`, [enabled, userId]);
  }

  it('keeps every existing account, enabled or disabled, with no time', async () => {
    const realm = await seedRealm();
    const enabled = await seedUser(realm);
    const disabled = await seedUser(realm, false);

    await migrate();

    expect(await notValidBefore(enabled)).toBeNull();
    expect(await notValidBefore(disabled)).toBeNull();
  });

  it('lets the previous release insert an account without the column', async () => {
    const realm = await seedRealm();
    await migrate();

    const user = await seedUser(realm);

    expect(await notValidBefore(user)).toBeNull();
  });

  it('records the time of the change when an account is disabled by a plain UPDATE', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();

    const start = Date.now();
    await setEnabled(user, false);
    const end = Date.now();

    const recorded = await notValidBefore(user);
    expect(recorded).not.toBeNull();
    expect(recorded).toBeGreaterThanOrEqual(start);
    expect(recorded).toBeLessThanOrEqual(end);
  });

  it('takes the time of the row change, not the start of its transaction', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();

    const client = await db().connect();
    try {
      await client.query('BEGIN');
      const {
        rows: [started],
      } = await client.query<{ at: string }>(
        `SELECT floor(EXTRACT(EPOCH FROM now()) * 1000)::bigint AS at`
      );
      await client.query(`SELECT pg_sleep(0.2)`);
      await client.query(`UPDATE users SET enabled = false WHERE id = $1`, [user]);
      await client.query('COMMIT');

      expect(await notValidBefore(user)).toBeGreaterThanOrEqual(Number(started.at) + 200);
    } finally {
      client.release();
    }
  });

  it('keeps the time when the account is enabled again, and moves it forward when disabled again', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();

    await setEnabled(user, false);
    const first = await notValidBefore(user);
    await setEnabled(user, true);
    expect(await notValidBefore(user)).toBe(first);

    await db().query(`SELECT pg_sleep(0.01)`);
    await setEnabled(user, false);
    const second = await notValidBefore(user);
    expect(second).toBeGreaterThan(first as number);
  });

  it('does not move the time for an account that was already disabled', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();
    await setEnabled(user, false);
    const first = await notValidBefore(user);

    await db().query(`SELECT pg_sleep(0.01)`);
    await setEnabled(user, false);

    expect(await notValidBefore(user)).toBe(first);
  });

  it('records a time for an account the previous release left disabled once it is enabled and disabled again', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm, false);
    await migrate();

    await setEnabled(user, true);
    expect(await notValidBefore(user)).toBeNull();
    await setEnabled(user, false);

    expect(await notValidBefore(user)).not.toBeNull();
  });

  it('refuses an update that clears the time or moves it back, also together with enabling', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();
    await setEnabled(user, false);
    const recorded = await notValidBefore(user);

    const refused = {
      code: '23514',
      constraint: 'users_not_valid_before_forward_only',
      table: 'users',
    };
    await expect(
      db().query(`UPDATE users SET enabled = true, not_valid_before = NULL WHERE id = $1`, [user])
    ).rejects.toMatchObject(refused);
    await expect(
      db().query(`UPDATE users SET not_valid_before = not_valid_before - 1 WHERE id = $1`, [user])
    ).rejects.toMatchObject(refused);

    expect(await notValidBefore(user)).toBe(recorded);
  });

  it('lets an update move the time forward, and keeps the later of that and the disablement', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();
    const later = Date.now() + 3_600_000;

    await db().query(`UPDATE users SET not_valid_before = $1 WHERE id = $2`, [later, user]);
    expect(await notValidBefore(user)).toBe(later);

    await setEnabled(user, false);
    expect(await notValidBefore(user)).toBe(later);
  });

  it('leaves the time alone on an update of other columns', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();
    await setEnabled(user, false);
    const recorded = await notValidBefore(user);

    await db().query(`UPDATE users SET last_login_at = 1, first_name = 'A' WHERE id = $1`, [user]);

    expect(await notValidBefore(user)).toBe(recorded);
  });
});
