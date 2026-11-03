/**
 * Real-Postgres integration tests for the roles' database users (issue #498,
 * ADR-019 Decisions 8 and 9).
 *
 * What only a database can prove: once the grants map is applied, `web` and
 * `api` cannot read `realm_keys` and the signer can read and write it; `web`
 * cannot write `realm_public_keys`; a second run leaves the same grants; no
 * role user can alter, drop, create or truncate a table, nor change a row of
 * `audit_logs`; every role user reads the migrations journal its boot check
 * reads; and a run that would leave a user other privileges than the map's
 * (a user that is the owner, a superuser, one that does not exist, a grant
 * through PUBLIC) is refused and changes nothing. The auth server's suite
 * `database-users.integration.test.ts` runs each role's routes as its user.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Database, NewRealmKey } from '../../types';
import { type IntegrationDb, setupIntegrationDb } from '../repositories/integration-setup';
import { createRealmKeysRepository } from '../repositories/realm-keys.repository';
import { applyDatabaseUserGrants, checkDatabaseUserGrants, DatabaseUserGrantsError } from './apply';
import { DATABASE_ROLES, type DatabaseRole, type DatabaseUserAssignment } from './roles';

const USERS: DatabaseUserAssignment = {
  web: 'qauth_web',
  api: 'qauth_api',
  admin: 'qauth_admin',
  signer: 'qauth_signer',
  delivery: 'qauth_delivery',
};

/** A user `web` and `signer` share, as when they run in one process. */
const FRONT = 'qauth_front';

const PUBLIC_JWK = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
const PUBLISH_AT = 1_800_000_000_000;

/** One grant a user holds, as the catalogs store it. */
interface HeldGrant {
  kind: string;
  object: string;
  grantee: string;
  privilege: string;
}

describe('the roles’ database users (real Postgres, #498)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  const pools = new Map<string, Pool>();

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    // A container of its own: roles are cluster-wide and outlive the
    // database, so on a shared server their fixed names would meet the next
    // suite's.
    ctx = await setupIntegrationDb({ privateContainer: true });
    for (const user of [...Object.values(USERS), FRONT]) {
      await ctx.database.pool.query(`CREATE ROLE ${user} LOGIN PASSWORD '${user}'`);
    }
    await applyDatabaseUserGrants({ connectionString: ctx.connectionString }, USERS);
  }, 180_000);

  afterAll(async () => {
    await Promise.all([...pools.values()].map((pool) => pool.end()));
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function owner(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  function target() {
    if (!ctx) throw new Error('no ctx');
    return { connectionString: ctx.connectionString };
  }

  /** A pool that connects as `user`. */
  function as(user: string): Pool {
    if (!ctx) throw new Error('no ctx');
    let pool = pools.get(user);
    if (pool === undefined) {
      const url = new URL(ctx.connectionString);
      url.username = user;
      url.password = user;
      pool = new Pool({ connectionString: url.toString(), max: 2 });
      pools.set(user, pool);
    }
    return pool;
  }

  function roleUser(role: DatabaseRole): Pool {
    return as(USERS[role]);
  }

  /** The SQLSTATE behind a rejected promise. */
  async function sqlState(promise: Promise<unknown>): Promise<string> {
    try {
      await promise;
    } catch (error) {
      let current: unknown = error;
      while (current && typeof current === 'object') {
        const candidate = current as { code?: unknown; cause?: unknown };
        if (typeof candidate.code === 'string' && /^[0-9A-Z]{5}$/.test(candidate.code)) {
          return candidate.code;
        }
        current = candidate.cause;
      }
      throw error;
    }
    throw new Error('expected the statement to fail');
  }

  /** 42501, insufficient_privilege: what Postgres answers a statement a user may not run. */
  const DENIED = '42501';

  async function seedRealm(): Promise<string> {
    const { rows } = await owner().query<{ id: string }>(
      `INSERT INTO realms (name) VALUES ($1) RETURNING id`,
      [`realm-${Math.random().toString(36).slice(2)}`]
    );
    return rows[0].id;
  }

  function keyRow<T extends Partial<NewRealmKey>>(realmId: string, overrides: T): NewRealmKey & T {
    return {
      realmId,
      purpose: 'token_signing',
      algorithm: 'EdDSA',
      kid: `kid-${Math.random().toString(36).slice(2)}`,
      status: 'active',
      ciphertext: Buffer.from([0x00, 0x01, 0xfe, 0xff, 0x80]),
      iv: Buffer.alloc(12, 7),
      wrappedDek: Buffer.alloc(40, 9),
      kekRef: '0123456789abcdef',
      aadVersion: 1,
      ...overrides,
    };
  }

  /** Every grant the named users hold in the schemas, from the catalogs. */
  async function heldGrants(users: readonly string[]): Promise<HeldGrant[]> {
    const { rows } = await owner().query<HeldGrant>(
      `SELECT 'table' AS kind, n.nspname || '.' || c.relname AS object,
              a.grantee::regrole::text AS grantee, a.privilege_type AS privilege
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(c.relacl) a
        WHERE n.nspname IN ('public', 'drizzle') AND a.grantee::regrole::text = ANY($1::text[])
       UNION ALL
       SELECT 'column', n.nspname || '.' || c.relname || '.' || att.attname,
              a.grantee::regrole::text, a.privilege_type
         FROM pg_attribute att
         JOIN pg_class c ON c.oid = att.attrelid
         JOIN pg_namespace n ON n.oid = c.relnamespace
        CROSS JOIN LATERAL aclexplode(att.attacl) a
        WHERE n.nspname IN ('public', 'drizzle') AND a.grantee::regrole::text = ANY($1::text[])
       UNION ALL
       SELECT 'function', p.oid::regprocedure::text, a.grantee::regrole::text, a.privilege_type
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        CROSS JOIN LATERAL aclexplode(p.proacl) a
        WHERE n.nspname = 'public' AND a.grantee::regrole::text = ANY($1::text[])
       UNION ALL
       SELECT 'schema', n.nspname, a.grantee::regrole::text, a.privilege_type
         FROM pg_namespace n CROSS JOIN LATERAL aclexplode(n.nspacl) a
        WHERE n.nspname IN ('public', 'drizzle') AND a.grantee::regrole::text = ANY($1::text[])
       ORDER BY 1, 2, 3, 4`,
      [users]
    );
    return rows;
  }

  it('keeps realm_keys from web and api, and lets the signer read and write it', async () => {
    const realmId = await seedRealm();
    for (const role of ['web', 'api', 'admin', 'delivery'] as const) {
      await expect(sqlState(roleUser(role).query(`SELECT * FROM realm_keys`)), role).resolves.toBe(
        DENIED
      );
      await expect(
        sqlState(roleUser(role).query(`SELECT kid FROM realm_keys`)),
        role
      ).resolves.toBe(DENIED);
    }

    // The signer's own repository, on its own user: it stores a key with its
    // public row, reads it, retires it and deletes it.
    const keys = createRealmKeysRepository(drizzle(roleUser('signer')) as unknown as Database);
    const scoped = { purpose: 'upstream_client_assertion', algorithm: 'RS256', scopeId: 'idp-1' };
    const created = await keys.create({
      key: keyRow(realmId, { ...scoped, publishAt: PUBLISH_AT }),
      publicJwk: PUBLIC_JWK,
    });
    expect(await keys.findByKid(realmId, created.kid)).toMatchObject({ status: 'active' });
    await expect(
      keys.updateStatus(realmId, created.kid, {
        status: 'retired',
        retireAt: PUBLISH_AT + 1,
        unpublishAt: PUBLISH_AT + 2,
      })
    ).resolves.toMatchObject({ status: 'retired' });
    await expect(keys.deleteByScope(realmId, scoped.purpose, scoped.scopeId)).resolves.toEqual([
      created.kid,
    ]);
    await expect(keys.findByKid(realmId, created.kid)).resolves.toBeUndefined();
  });

  it('lets every role read realm_public_keys and only the signer write it', async () => {
    const realmId = await seedRealm();
    const keys = createRealmKeysRepository(drizzle(roleUser('signer')) as unknown as Database);
    const created = await keys.create({
      key: keyRow(realmId, { publishAt: PUBLISH_AT }),
      publicJwk: PUBLIC_JWK,
    });
    for (const role of DATABASE_ROLES) {
      const { rows } = await roleUser(role).query(
        `SELECT kid FROM realm_public_keys WHERE realm_id = $1`,
        [realmId]
      );
      expect(rows, role).toEqual([{ kid: created.kid }]);
    }
    for (const role of ['web', 'api', 'admin', 'delivery'] as const) {
      const user = roleUser(role);
      await expect(
        sqlState(
          user.query(
            `INSERT INTO realm_public_keys (realm_id, kid, purpose, algorithm, public_jwk, publish_at)
             VALUES ($1, 'forged', 'token_signing', 'EdDSA', $2, $3)`,
            [realmId, PUBLIC_JWK, PUBLISH_AT]
          )
        ),
        role
      ).resolves.toBe(DENIED);
      await expect(
        sqlState(user.query(`UPDATE realm_public_keys SET unpublish_at = 0`)),
        role
      ).resolves.toBe(DENIED);
      await expect(sqlState(user.query(`DELETE FROM realm_public_keys`)), role).resolves.toBe(
        DENIED
      );
    }
  });

  it('gives the same grants when it runs again, and finds nothing to change', async () => {
    const users = Object.values(USERS);
    const before = await heldGrants(users);
    expect(before).toContainEqual({
      kind: 'table',
      object: 'public.realm_keys',
      grantee: USERS.signer,
      privilege: 'SELECT',
    });
    expect(before.filter((grant) => grant.object === 'public.realm_keys')).toHaveLength(4);

    const report = await applyDatabaseUserGrants(target(), USERS);
    expect(report.users.map((grants) => grants.user)).toEqual(users);
    expect(await heldGrants(users)).toEqual(before);
    await expect(checkDatabaseUserGrants(target(), USERS)).resolves.toEqual([]);
  });

  it('lets no role user change the schema', async () => {
    for (const role of DATABASE_ROLES) {
      const user = roleUser(role);
      await expect(
        sqlState(user.query(`ALTER TABLE users ADD COLUMN forged integer`)),
        role
      ).resolves.toBe(DENIED);
      await expect(
        sqlState(user.query(`ALTER TABLE realm_keys DISABLE ROW LEVEL SECURITY`)),
        role
      ).resolves.toBe(DENIED);
      await expect(sqlState(user.query(`DROP TABLE audit_logs`)), role).resolves.toBe(DENIED);
      await expect(sqlState(user.query(`DROP TABLE realm_keys`)), role).resolves.toBe(DENIED);
      await expect(
        sqlState(user.query(`CREATE TABLE public.forged (id integer)`)),
        role
      ).resolves.toBe(DENIED);
      await expect(sqlState(user.query(`TRUNCATE events`)), role).resolves.toBe(DENIED);
      await expect(
        sqlState(user.query(`CREATE TABLE drizzle.forged (id integer)`)),
        role
      ).resolves.toBe(DENIED);
    }
  });

  it('lets no role user write, change or delete an audit_logs row', async () => {
    for (const role of DATABASE_ROLES) {
      const user = roleUser(role);
      await expect(
        sqlState(user.query(`INSERT INTO audit_logs DEFAULT VALUES`)),
        role
      ).resolves.toBe(DENIED);
      await expect(sqlState(user.query(`UPDATE audit_logs SET id = id`)), role).resolves.toBe(
        DENIED
      );
      await expect(sqlState(user.query(`DELETE FROM audit_logs`)), role).resolves.toBe(DENIED);
    }
  });

  it('lets every role user read the migrations journal its boot reads, and none write it', async () => {
    for (const role of DATABASE_ROLES) {
      const user = roleUser(role);
      const { rows } = await user.query<{ applied: number }>(
        `SELECT count(*)::int AS applied FROM drizzle.__drizzle_migrations`
      );
      expect(rows[0].applied, role).toBeGreaterThan(0);
      await expect(
        sqlState(user.query(`DELETE FROM drizzle.__drizzle_migrations`)),
        role
      ).resolves.toBe(DENIED);
    }
  });

  it('gives a user two roles share the grants of both', async () => {
    const shared = { ...USERS, web: FRONT, signer: FRONT };
    await applyDatabaseUserGrants(target(), shared);
    const front = as(FRONT);
    await expect(front.query(`SELECT count(*) FROM realm_keys`)).resolves.toBeDefined();
    await expect(front.query(`SELECT count(*) FROM authorization_codes`)).resolves.toBeDefined();
    // The users it did not name keep their grants: the web user still
    // cannot read the keys, and both assignments check clean.
    await expect(sqlState(roleUser('web').query(`SELECT * FROM realm_keys`))).resolves.toBe(DENIED);
    await expect(checkDatabaseUserGrants(target(), shared)).resolves.toEqual([]);
    await expect(checkDatabaseUserGrants(target(), USERS)).resolves.toEqual([]);
  });

  describe('a run it refuses changes nothing', () => {
    async function expectRefused(users: DatabaseUserAssignment, problem: RegExp): Promise<void> {
      const before = await heldGrants(Object.values(USERS));
      const refusal = applyDatabaseUserGrants(target(), users);
      await expect(refusal).rejects.toBeInstanceOf(DatabaseUserGrantsError);
      await expect(refusal).rejects.toMatchObject({
        problems: expect.arrayContaining([expect.stringMatching(problem)]),
      });
      expect(await heldGrants(Object.values(USERS))).toEqual(before);
    }

    it('refuses a user that does not exist', async () => {
      await expectRefused({ ...USERS, delivery: 'qauth_nobody' }, /qauth_nobody/);
    });

    it('refuses the owner of the tables, and a superuser', async () => {
      const { rows } = await owner().query<{ name: string }>(`SELECT current_user AS name`);
      await expectRefused({ ...USERS, web: rows[0].name }, new RegExp(rows[0].name));
      await owner().query(`CREATE ROLE qauth_root LOGIN SUPERUSER PASSWORD 'qauth_root'`);
      await expectRefused({ ...USERS, admin: 'qauth_root' }, /qauth_root/);
    });

    it('refuses grants PUBLIC holds beyond the map, and the check names them', async () => {
      await owner().query(`GRANT SELECT ON realm_keys TO PUBLIC`);
      try {
        await expectRefused(USERS, /holds SELECT on realm_keys/);
        const problems = await checkDatabaseUserGrants(target(), USERS);
        expect(problems).toContainEqual(expect.stringMatching(/"qauth_web".*SELECT on realm_keys/));
      } finally {
        await owner().query(`REVOKE SELECT ON realm_keys FROM PUBLIC`);
      }
      await expect(checkDatabaseUserGrants(target(), USERS)).resolves.toEqual([]);
    });
  });
});
