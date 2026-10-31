/**
 * Seed-then-migrate test for migration 0044: `users.not_valid_before` (#748).
 *
 * The migration applies to a schema that holds accounts, enabled and disabled:
 * an enabled one keeps its row with no time, a disabled one gets the time the
 * migration ran, and an insert without the column, as the previous release
 * makes during a rolling upgrade, still works. From then on disabling an
 * account, by any `UPDATE`, records the time its transaction commits;
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

  /**
   * The database's clock, in epoch milliseconds, as the triggers read it: the
   * bounds of a recorded time, which the host's clock may disagree with.
   */
  async function dbNow(): Promise<number> {
    const {
      rows: [now],
    } = await db().query<{ now: string }>(
      `SELECT floor(EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint AS now`
    );
    return Number(now.now);
  }

  async function setEnabled(userId: string, enabled: boolean): Promise<void> {
    await db().query(`UPDATE users SET enabled = $1 WHERE id = $2`, [enabled, userId]);
  }

  it('keeps an enabled account with no time, and gives one already disabled the time of the migration', async () => {
    const realm = await seedRealm();
    const enabled = await seedUser(realm);
    const disabled = await seedUser(realm, false);

    const start = await dbNow();
    await migrate();
    const end = await dbNow();

    expect(await notValidBefore(enabled)).toBeNull();
    // Disabled at a time nobody recorded: what it holds was issued before now.
    const recorded = await notValidBefore(disabled);
    expect(recorded).toBeGreaterThanOrEqual(start);
    expect(recorded).toBeLessThanOrEqual(end);
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

    const start = await dbNow();
    await setEnabled(user, false);
    const end = await dbNow();

    const recorded = await notValidBefore(user);
    expect(recorded).not.toBeNull();
    expect(recorded).toBeGreaterThanOrEqual(start);
    expect(recorded).toBeLessThanOrEqual(end);
  });

  it('records the time the disabling transaction commits, not when it began or changed the row', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();

    const client = await db().connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE users SET enabled = false WHERE id = $1`, [user]);
      const {
        rows: [inside],
      } = await client.query<{ not_valid_before: string }>(
        `SELECT not_valid_before FROM users WHERE id = $1`,
        [user]
      );
      // Other transactions read the account as enabled until the commit, and
      // may sign it in meanwhile.
      await client.query(`SELECT pg_sleep(0.3)`);
      const beforeCommit = await dbNow();
      await client.query('COMMIT');

      const committed = await notValidBefore(user);
      expect(committed).toBeGreaterThanOrEqual(beforeCommit);
      expect(committed).toBeGreaterThanOrEqual(Number(inside.not_valid_before) + 300);
    } finally {
      client.release();
    }
  });

  it('moves nothing at commit for an account disabled and enabled again in one transaction', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm);
    await migrate();

    const client = await db().connect();
    try {
      await client.query('BEGIN');
      await client.query(`UPDATE users SET enabled = false WHERE id = $1`, [user]);
      const {
        rows: [inside],
      } = await client.query<{ not_valid_before: string }>(
        `SELECT not_valid_before FROM users WHERE id = $1`,
        [user]
      );
      await client.query(`UPDATE users SET enabled = true WHERE id = $1`, [user]);
      await client.query(`SELECT pg_sleep(0.05)`);
      await client.query('COMMIT');

      expect(await notValidBefore(user)).toBe(Number(inside.not_valid_before));
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

  it('keeps the time of the migration for an account the previous release left disabled, once it is enabled', async () => {
    const realm = await seedRealm();
    const user = await seedUser(realm, false);
    await migrate();
    const recorded = await notValidBefore(user);

    await setEnabled(user, true);

    expect(recorded).not.toBeNull();
    expect(await notValidBefore(user)).toBe(recorded);
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
