/**
 * Seed-then-migrate test for migration 0040: a realm's dynamic registration
 * allowlist cannot hold a scope with the reserved `admin:` prefix (ADR-019
 * Decision 7, #507).
 *
 * The migration drops such entries from an allowlist that already has them,
 * keeping the others in their order, and then adds a CHECK that refuses them
 * for every writer. The CHECK and `isReservedAdminScope` (shared-validation)
 * must agree, which the last test pins.
 *
 * Requires Docker; self-skips without it. The schema is rebuilt from scratch
 * and upgraded through 0039, then 0040, so a later migration cannot change
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
import { isReservedAdminScope } from '@qauth-labs/shared-validation';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const MIGRATION_IDX = 40;
const CONSTRAINT = 'realms_dynamic_registration_scopes_not_admin';

describe('migration 0040 — no admin: scope in the dynamic registration allowlist (seed-then-migrate)', () => {
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

  async function seedRealm(name: string, scopes: unknown, updatedAt = 1_700_000_000_000) {
    await db().query(
      `INSERT INTO realms (name, dynamic_registration_allowed_scopes, updated_at)
       VALUES ($1, $2::jsonb, $3)`,
      [name, JSON.stringify(scopes), updatedAt]
    );
  }

  async function allowlistOf(name: string): Promise<{ scopes: unknown; updatedAt: string }> {
    const {
      rows: [row],
    } = await db().query<{ scopes: unknown; updated_at: string }>(
      `SELECT dynamic_registration_allowed_scopes AS scopes, updated_at FROM realms WHERE name = $1`,
      [name]
    );
    return { scopes: row.scopes, updatedAt: row.updated_at };
  }

  it('drops the admin: entries an allowlist already holds and keeps the rest in order', async () => {
    await seedRealm('mixed', ['openid', 'admin:read', 'mcp:read', 'ADMIN:security', 'profile']);
    await seedRealm('only-admin', ['admin:write']);
    await seedRealm('clean', ['openid', 'agent:admin', 'example:admin', 'administrator']);
    await seedRealm('empty', []);
    await migrate();

    expect((await allowlistOf('mixed')).scopes).toEqual(['openid', 'mcp:read', 'profile']);
    expect((await allowlistOf('only-admin')).scopes).toEqual([]);
    expect(await allowlistOf('clean')).toEqual({
      scopes: ['openid', 'agent:admin', 'example:admin', 'administrator'],
      updatedAt: '1700000000000',
    });
    expect((await allowlistOf('empty')).scopes).toEqual([]);
  });

  it('empties a value that is not a list but would fail the CHECK, and leaves other values', async () => {
    await seedRealm('string', 'admin:read openid');
    await seedRealm('harmless-string', 'openid');
    await seedRealm('nested', [['admin:read'], 'openid']);
    await migrate();

    expect((await allowlistOf('string')).scopes).toEqual([]);
    expect((await allowlistOf('harmless-string')).scopes).toBe('openid');
    expect((await allowlistOf('nested')).scopes).toEqual(['openid']);
  });

  it('marks a realm whose allowlist it changed as updated', async () => {
    await seedRealm('mixed', ['openid', 'admin:read']);
    await migrate();
    expect(Number((await allowlistOf('mixed')).updatedAt)).toBeGreaterThan(1_700_000_000_000);
  });

  it('then refuses an admin: scope on insert and on update', async () => {
    await migrate();
    await expect(seedRealm('new', ['openid', 'admin:read'])).rejects.toMatchObject({
      code: '23514',
      constraint: CONSTRAINT,
    });
    await seedRealm('existing', ['openid']);
    await expect(
      db().query(
        `UPDATE realms SET dynamic_registration_allowed_scopes = '["openid","Admin:Write"]'::jsonb
         WHERE name = 'existing'`
      )
    ).rejects.toMatchObject({ code: '23514', constraint: CONSTRAINT });
    // Other columns of the row still change freely.
    await db().query(`UPDATE realms SET verify_email = false WHERE name = 'existing'`);
  });

  it('agrees with isReservedAdminScope on every case it is asked about', async () => {
    await migrate();
    const cases = [
      'admin:read',
      'admin:write',
      'admin:security',
      'admin:',
      'ADMIN:read',
      'aDmIn:x',
      'admin',
      'administrator',
      'admins:read',
      'agent:admin',
      'example:admin',
      ' admin:read',
      'xadmin:read',
      'ADMİN:read',
      'admın:read',
    ];
    for (const [index, scope] of cases.entries()) {
      const insert = seedRealm(`case-${index}`, [scope]);
      if (isReservedAdminScope(scope)) {
        await expect(insert, scope).rejects.toMatchObject({ constraint: CONSTRAINT });
      } else {
        await expect(insert, scope).resolves.toBeUndefined();
      }
    }
  });
});
