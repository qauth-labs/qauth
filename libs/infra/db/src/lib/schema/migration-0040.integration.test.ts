/**
 * Seed-then-migrate test for migration 0040: a realm's dynamic registration
 * allowlist cannot hold a scope in the reserved `qauth:` namespace (ADR-019
 * Decision 7, #507).
 *
 * The migration drops such entries from an allowlist that already has them,
 * keeping the others in their order, and then adds a CHECK that refuses them
 * for every writer. It fails closed: a list the cleanup would leave empty, or
 * a value that is not a list, stops the migration before anything changes,
 * because the server fills an empty list from
 * DEFAULT_DYNAMIC_REGISTRATION_SCOPES. The CHECK and `isReservedQauthScope`
 * (shared-validation) must agree, which the last test pins.
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
import { isReservedQauthScope } from '@qauth-labs/shared-validation';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

const MIGRATION_IDX = 40;
const CONSTRAINT = 'realms_dynamic_registration_scopes_not_qauth';

describe('migration 0040 — no qauth: scope in the dynamic registration allowlist (seed-then-migrate)', () => {
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

  /** Whether the migration ran: its CHECK exists. */
  async function constraintExists(): Promise<boolean> {
    const { rows } = await db().query(`SELECT 1 FROM pg_constraint WHERE conname = $1`, [
      CONSTRAINT,
    ]);
    return rows.length === 1;
  }

  /** The error a failed run raised, from Postgres, under drizzle's wrapper if any. */
  async function migrationError(): Promise<{ message: string; hint?: string }> {
    const error = await migrate().then(
      () => undefined,
      (err: unknown) => err
    );
    expect(error, 'the migration ran').toBeDefined();
    const cause = (error as { cause?: unknown }).cause ?? error;
    return cause as { message: string; hint?: string };
  }

  it('drops the qauth: entries an allowlist already holds and keeps the rest in order', async () => {
    await seedRealm('mixed', [
      'openid',
      'qauth:admin:read',
      'mcp:read',
      'QAUTH:security',
      'profile',
    ]);
    await seedRealm('clean', ['openid', 'admin:read', 'admin:org', 'example:qauth', 'qauthx:read']);
    await seedRealm('empty', []);
    await migrate();

    expect((await allowlistOf('mixed')).scopes).toEqual(['openid', 'mcp:read', 'profile']);
    // Other servers' admin: scopes are ordinary scopes: the row is untouched.
    expect(await allowlistOf('clean')).toEqual({
      scopes: ['openid', 'admin:read', 'admin:org', 'example:qauth', 'qauthx:read'],
      updatedAt: '1700000000000',
    });
    expect((await allowlistOf('empty')).scopes).toEqual([]);
  });

  it('drops a nested list that holds a qauth: scope, and leaves a value that is not a list and holds none', async () => {
    await seedRealm('harmless-string', 'openid');
    await seedRealm('nested', [['qauth:admin:read'], 'openid']);
    await migrate();

    expect((await allowlistOf('harmless-string')).scopes).toBe('openid');
    expect((await allowlistOf('nested')).scopes).toEqual(['openid']);
  });

  it('marks a realm whose allowlist it changed as updated', async () => {
    await seedRealm('mixed', ['openid', 'qauth:admin:read']);
    await migrate();
    expect(Number((await allowlistOf('mixed')).updatedAt)).toBeGreaterThan(1_700_000_000_000);
  });

  // An empty list is read as unset and filled from the environment's default:
  // emptying it would widen the realm's policy.
  it('stops, naming the realms and the fix, when the cleanup would leave a list empty', async () => {
    await seedRealm('only-qauth', ['qauth:admin:write', 'QAuth:admin:read']);
    await seedRealm('also-only', [['qauth:admin:read']]);
    await seedRealm('mixed', ['openid', 'qauth:admin:read']);

    const error = await migrationError();
    expect(error.message).toMatch(/^migration 0040: the dynamic registration allowlist of realm /);
    expect(error.message).toContain('also-only (');
    expect(error.message).toContain('only-qauth (');
    expect(error.message).not.toContain('mixed');
    expect(error.hint).toContain('UPDATE realms SET dynamic_registration_allowed_scopes');

    // Nothing changed: the run rolled back before the cleanup.
    expect(await constraintExists()).toBe(false);
    expect((await allowlistOf('only-qauth')).scopes).toEqual([
      'qauth:admin:write',
      'QAuth:admin:read',
    ]);
    expect((await allowlistOf('mixed')).scopes).toEqual(['openid', 'qauth:admin:read']);

    // Once the operator sets the lists, the migration runs.
    await db().query(
      `UPDATE realms SET dynamic_registration_allowed_scopes = '["openid"]'::jsonb
       WHERE name IN ('only-qauth', 'also-only')`
    );
    await migrate();
    expect(await constraintExists()).toBe(true);
    expect((await allowlistOf('mixed')).scopes).toEqual(['openid']);
  });

  it('stops for a value that is not a list and holds a qauth: scope, rather than emptying it', async () => {
    await seedRealm('string', 'qauth:admin:read openid');
    const error = await migrationError();
    expect(error.message).toContain('string (');
    expect(await constraintExists()).toBe(false);
    expect((await allowlistOf('string')).scopes).toBe('qauth:admin:read openid');
  });

  it('then refuses a qauth: scope on insert and on update, and accepts admin: scopes', async () => {
    await migrate();
    await expect(seedRealm('new', ['openid', 'qauth:admin:read'])).rejects.toMatchObject({
      code: '23514',
      constraint: CONSTRAINT,
    });
    await seedRealm('existing', ['openid', 'admin:read', 'admin:org']);
    await expect(
      db().query(
        `UPDATE realms SET dynamic_registration_allowed_scopes = '["openid","QAuth:Admin:Write"]'::jsonb
         WHERE name = 'existing'`
      )
    ).rejects.toMatchObject({ code: '23514', constraint: CONSTRAINT });
    // Other columns of the row still change freely.
    await db().query(`UPDATE realms SET verify_email = false WHERE name = 'existing'`);
  });

  it('agrees with isReservedQauthScope on every case it is asked about', async () => {
    await migrate();
    const cases = [
      'qauth:admin:read',
      'qauth:admin:write',
      'qauth:admin:security',
      'qauth:',
      'QAUTH:admin:read',
      'qAuTh:x',
      'qauth',
      'qauthx:read',
      'admin:read',
      'admin:security',
      'admin:org',
      'example:qauth:read',
      ' qauth:admin:read',
      'q\u0430uth:admin:read',
      '\uff51\uff41\uff55\uff54\uff48:admin:read',
    ];
    for (const [index, scope] of cases.entries()) {
      const insert = seedRealm(`case-${index}`, [scope]);
      if (isReservedQauthScope(scope)) {
        await expect(insert, scope).rejects.toMatchObject({ constraint: CONSTRAINT });
      } else {
        await expect(insert, scope).resolves.toBeUndefined();
      }
    }
  });
});
