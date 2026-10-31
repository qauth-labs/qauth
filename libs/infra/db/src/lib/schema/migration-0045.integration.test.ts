/**
 * Seed-then-migrate test for migration 0045: the realm policies on the realm
 * row (#516).
 *
 * The migration applies to a schema that holds the data of the previous
 * release: realms with their hosts, an operator realm whose ceiling and
 * dynamic registration allowlist an operator set, accounts. Every realm gets
 * an empty document and counter 0 (no policies yet: the boot step fills
 * them), and every column it had keeps its value. An insert and an update
 * without the new columns, as the previous release makes during a rolling
 * upgrade, still work. From then on the trigger raises the counter whenever
 * the policies change, whoever writes them, and refuses to lower it; the
 * CHECKs keep the three columns consistent.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0044, then 0045, so a later migration cannot change
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

const MIGRATION_IDX = 45;

interface PolicyColumns {
  policies: unknown;
  policy_schema_version: string | null;
  policies_version: number;
}

describe('migration 0045 — realm policies (seed-then-migrate)', () => {
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

  /** The default realm as the previous release leaves it: issuer, host, operator flag, settings. */
  async function seedPreviousRelease(): Promise<{ master: string; other: string; user: string }> {
    const {
      rows: [master],
    } = await db().query<{ id: string }>(
      `INSERT INTO realms (name, issuer, is_operator, max_environment_laxity,
                           dynamic_registration_allowed_scopes, sso_max_lifespan)
       VALUES ('master', 'https://auth.example.com', true, 'development',
               '["openid", "profile", "offline_access"]'::jsonb, 86400)
       RETURNING id`
    );
    await db().query(
      `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ('auth.example.com', $1, 'primary')`,
      [master.id]
    );
    const {
      rows: [other],
    } = await db().query<{ id: string }>(`INSERT INTO realms (name) VALUES ('other') RETURNING id`);
    const {
      rows: [user],
    } = await db().query<{ id: string }>(
      `INSERT INTO users (realm_id, enabled) VALUES ($1, true) RETURNING id`,
      [master.id]
    );
    return { master: master.id, other: other.id, user: user.id };
  }

  async function policyColumns(realmId: string): Promise<PolicyColumns> {
    const {
      rows: [row],
    } = await db().query<PolicyColumns>(
      `SELECT policies, policy_schema_version, policies_version FROM realms WHERE id = $1`,
      [realmId]
    );
    return row;
  }

  /** Give a realm policies by hand, as the policy store's write does. */
  async function givePolicies(realmId: string): Promise<void> {
    await db().query(
      `UPDATE realms
          SET policies = '{"password": {"minScore": 2}}'::jsonb,
              policy_schema_version = '1-rc.0',
              policies_version = 1
        WHERE id = $1`,
      [realmId]
    );
  }

  it('applies on the data of the previous release: no policies yet, every column as it was', async () => {
    const seeded = await seedPreviousRelease();
    const {
      rows: [beforeRow],
    } = await db().query(`SELECT * FROM realms WHERE id = $1`, [seeded.master]);

    await migrate();

    const {
      rows: [afterRow],
    } = await db().query(`SELECT * FROM realms WHERE id = $1`, [seeded.master]);
    const { policies, policy_schema_version, policies_version, ...kept } = afterRow;
    expect(kept).toEqual(beforeRow);
    expect({ policies, policy_schema_version, policies_version }).toEqual({
      policies: {},
      policy_schema_version: null,
      policies_version: 0,
    });
    expect(await policyColumns(seeded.other)).toEqual({
      policies: {},
      policy_schema_version: null,
      policies_version: 0,
    });
    const { rows: hosts } = await db().query(`SELECT host FROM realm_hosts`);
    expect(hosts).toEqual([{ host: 'auth.example.com' }]);
    const { rows: users } = await db().query(`SELECT id FROM users`);
    expect(users).toEqual([{ id: seeded.user }]);
  });

  it('takes an insert and an update of the previous release, which name no new column', async () => {
    await migrate();

    const {
      rows: [realm],
    } = await db().query<{ id: string }>(
      `INSERT INTO realms (name, max_environment_laxity) VALUES ('rolling', 'staging') RETURNING id`
    );
    await db().query(
      `UPDATE realms SET dynamic_registration_allowed_scopes = '["openid"]'::jsonb WHERE id = $1`,
      [realm.id]
    );

    // A realm with no policies keeps counter 0: the boot step fills it.
    expect(await policyColumns(realm.id)).toEqual({
      policies: {},
      policy_schema_version: null,
      policies_version: 0,
    });
  });

  it('raises the counter when an UPDATE changes a policy column or the document and leaves the counter', async () => {
    const { master } = await seedPreviousRelease();
    await migrate();
    await givePolicies(master);

    await db().query(`UPDATE realms SET max_environment_laxity = 'staging' WHERE id = $1`, [
      master,
    ]);
    expect((await policyColumns(master)).policies_version).toBe(2);

    await db().query(
      `UPDATE realms SET dynamic_registration_allowed_scopes = '["openid"]'::jsonb WHERE id = $1`,
      [master]
    );
    await db().query(`UPDATE realms SET access_token_lifespan = 300 WHERE id = $1`, [master]);
    await db().query(`UPDATE realms SET refresh_token_lifespan = 3600 WHERE id = $1`, [master]);
    await db().query(
      `UPDATE realms SET policies = '{"password": {"minScore": 3}}'::jsonb WHERE id = $1`,
      [master]
    );
    await db().query(`UPDATE realms SET policy_schema_version = '1-rc.1' WHERE id = $1`, [master]);
    expect((await policyColumns(master)).policies_version).toBe(7);
  });

  it('leaves the counter of an UPDATE that sets it, and of one that changes no policy', async () => {
    const { master } = await seedPreviousRelease();
    await migrate();
    await givePolicies(master);

    // The policy store's write: the counter it sets, once.
    await db().query(
      `UPDATE realms SET access_token_lifespan = 300, policies_version = 2 WHERE id = $1`,
      [master]
    );
    expect((await policyColumns(master)).policies_version).toBe(2);

    // The same values again, and a column that is no policy.
    await db().query(`UPDATE realms SET access_token_lifespan = 300 WHERE id = $1`, [master]);
    await db().query(`UPDATE realms SET sso_max_lifespan = 3600, updated_at = 5 WHERE id = $1`, [
      master,
    ]);
    expect((await policyColumns(master)).policies_version).toBe(2);
  });

  it('keeps counter 0 on a realm with no policies whose policy column changes', async () => {
    const { master } = await seedPreviousRelease();
    await migrate();

    await db().query(`UPDATE realms SET max_environment_laxity = 'production' WHERE id = $1`, [
      master,
    ]);

    expect((await policyColumns(master)).policies_version).toBe(0);
  });

  it('refuses to lower the counter, so an ETag never names two documents', async () => {
    const { master } = await seedPreviousRelease();
    await migrate();
    await givePolicies(master);

    await expect(
      db().query(`UPDATE realms SET policies_version = 0 WHERE id = $1`, [master])
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_policies_version_forward_only' });
    expect((await policyColumns(master)).policies_version).toBe(1);
  });

  it('refuses policies without a schema version, a document that is no object and a bad version', async () => {
    const { master, other } = await seedPreviousRelease();
    await migrate();

    await expect(
      db().query(`UPDATE realms SET policies_version = 1 WHERE id = $1`, [master])
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_policies_complete' });
    await expect(
      db().query(
        `UPDATE realms SET policies_version = 1, policy_schema_version = '1-rc.0',
                           access_token_lifespan = NULL WHERE id = $1`,
        [master]
      )
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_policies_complete' });
    await expect(
      db().query(`UPDATE realms SET policies = '[]'::jsonb WHERE id = $1`, [master])
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_policies_object' });
    for (const version of ['v1', '1-rc', '1-rc.01', '0', '1.0']) {
      await expect(
        db().query(`UPDATE realms SET policy_schema_version = $2 WHERE id = $1`, [other, version])
      ).rejects.toMatchObject({ code: '23514', constraint: 'realms_policy_schema_version_format' });
    }
    await expect(
      db().query(
        `INSERT INTO realms (name, policies_version, policy_schema_version)
         VALUES ('negative', -1, '1-rc.0')`
      )
    ).rejects.toMatchObject({ code: '23514', constraint: 'realms_policies_version_not_negative' });
    for (const version of ['1-rc.0', '1-rc.12', '1', '2']) {
      await db().query(`UPDATE realms SET policy_schema_version = $2 WHERE id = $1`, [
        other,
        version,
      ]);
    }
  });
});
