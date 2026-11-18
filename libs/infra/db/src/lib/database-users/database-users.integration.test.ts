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
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip, testPrimaryCredential } from '@qauth-labs/shared-testing';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type { Database, NewRealmKey } from '../../types';
import { createAdminActSessionsRepository } from '../repositories/admin-act-sessions.repository';
import { createAdminAuditLogRepository } from '../repositories/admin-audit-log.repository';
import { type IntegrationDb, setupIntegrationDb } from '../repositories/integration-setup';
import { createRealmKeysRepository } from '../repositories/realm-keys.repository';
import { createRealmsRepository } from '../repositories/realms.repository';
import { createUsersRepository } from '../repositories/users.repository';
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

    it('refuses a user that does not exist, and the check reports it', async () => {
      await expectRefused({ ...USERS, delivery: 'qauth_nobody' }, /qauth_nobody/);
      // The check returns the refusal instead of failing on the drift queries.
      await expect(
        checkDatabaseUserGrants(target(), { ...USERS, delivery: 'qauth_nobody' })
      ).resolves.toEqual([expect.stringMatching(/"qauth_nobody" does not exist/)]);
    });

    it('refuses the owner of the tables, and a superuser', async () => {
      const { rows } = await owner().query<{ name: string }>(`SELECT current_user AS name`);
      await expectRefused({ ...USERS, web: rows[0].name }, new RegExp(rows[0].name));
      await owner().query(`CREATE ROLE qauth_root LOGIN SUPERUSER PASSWORD 'qauth_root'`);
      await expectRefused({ ...USERS, admin: 'qauth_root' }, /qauth_root/);
    });

    it('refuses a user that can SET ROLE to the signer’s user without inheriting it', async () => {
      await owner().query(`CREATE ROLE qauth_setrole LOGIN PASSWORD 'qauth_setrole'`);
      await owner().query(`GRANT ${USERS.signer} TO qauth_setrole WITH INHERIT FALSE`);
      await expectRefused({ ...USERS, web: 'qauth_setrole' }, /holds SELECT on realm_keys/);
    });

    it('refuses a user with an attribute or a predefined role that reaches past the grants', async () => {
      await owner().query(`CREATE ROLE qauth_replica LOGIN REPLICATION PASSWORD 'qauth_replica'`);
      await expectRefused({ ...USERS, api: 'qauth_replica' }, /qauth_replica.*REPLICATION/);
      await owner().query(`CREATE ROLE qauth_reader LOGIN PASSWORD 'qauth_reader'`);
      await owner().query(`GRANT pg_read_all_data TO qauth_reader`);
      await expectRefused({ ...USERS, api: 'qauth_reader' }, /qauth_reader.*pg_read_all_data/);
    });

    it('refuses a SECURITY DEFINER function PUBLIC may execute, and a sequence a user holds', async () => {
      await owner().query(
        `CREATE FUNCTION public.forged_definer() RETURNS integer LANGUAGE sql SECURITY DEFINER AS 'SELECT 1'`
      );
      try {
        await expectRefused(USERS, /PUBLIC may execute forged_definer\(\)/);
      } finally {
        await owner().query(`DROP FUNCTION public.forged_definer()`);
      }
      await owner().query(`CREATE SEQUENCE public.forged_sequence`);
      try {
        await owner().query(`GRANT USAGE ON SEQUENCE public.forged_sequence TO PUBLIC`);
        await expectRefused(USERS, /USAGE on the sequence forged_sequence/);
      } finally {
        await owner().query(`DROP SEQUENCE public.forged_sequence`);
      }
      await expect(checkDatabaseUserGrants(target(), USERS)).resolves.toEqual([]);
    });

    it('grants on public whatever search_path the owner sets, never on a same-named object elsewhere', async () => {
      // A schema ahead of public, with a function of the map's signature.
      await owner().query(`CREATE SCHEMA shadow`);
      await owner().query(
        `CREATE FUNCTION shadow.events_own_row(uuid) RETURNS boolean LANGUAGE sql AS 'SELECT true'`
      );
      await owner().query(`REVOKE ALL ON FUNCTION shadow.events_own_row(uuid) FROM PUBLIC`);
      const { rows } = await owner().query<{ name: string }>(`SELECT current_database() AS name`);
      const database = `"${rows[0].name}"`;
      await owner().query(`ALTER DATABASE ${database} SET search_path = shadow, public`);
      try {
        await applyDatabaseUserGrants(target(), USERS);
        const { rows: executable } = await owner().query<{ shadow: boolean; public: boolean }>(
          `SELECT has_function_privilege($1, 'shadow.events_own_row(uuid)', 'EXECUTE') AS shadow,
                  has_function_privilege($1, 'public.events_own_row(uuid)', 'EXECUTE') AS public`,
          [USERS.web]
        );
        expect(executable[0]).toEqual({ shadow: false, public: true });
        await expect(checkDatabaseUserGrants(target(), USERS)).resolves.toEqual([]);
      } finally {
        await owner().query(`ALTER DATABASE ${database} RESET search_path`);
        await owner().query(`DROP SCHEMA shadow CASCADE`);
      }
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

  it("lets api append an act-chain call's admin audit row through the functions alone, and reach nothing else of the log (#523)", async () => {
    if (!ctx) throw new Error('no ctx');
    const ownerDb = ctx.database.db;
    const name = `realm-${randomUUID()}`;
    const issuer = `https://${name}.example.test`;
    const realm = await createRealmsRepository(ownerDb).create({ name, issuer });
    const users = createUsersRepository(ownerDb);
    const user = await users.create({ realmId: realm.id }, testPrimaryCredential());
    const admin = await users.create({ realmId: realm.id }, testPrimaryCredential());
    const issuedAt = Date.now() - 1_000;
    const token = await ownerDb.transaction((tx) =>
      createAdminActSessionsRepository(ownerDb).create(tx, {
        realmId: realm.id,
        userId: user.id,
        adminRealmId: realm.id,
        adminUserId: admin.id,
        adminClientId: 'admin-console',
        approvalId: randomUUID(),
        operationId: 'users.actChainTokens.create',
        permissionIds: ['users.security'],
        tokenJti: randomUUID(),
        scopes: ['qauth:account:read'],
        createdAt: issuedAt,
        expiresAt: issuedAt + 10 * 60_000,
      })
    );

    // The account API's own repository, on its own user.
    const apiDb = drizzle(roleUser('api')) as unknown as Database;
    const audit = createAdminAuditLogRepository(apiDb);
    const appended = await apiDb.transaction((tx) =>
      audit.appendActChainCall(tx, {
        realmId: realm.id,
        tokenJti: token.tokenJti,
        actorId: admin.id,
        actorRealmId: realm.id,
        actChain: { sub: user.id, act: { sub: admin.id, iss: issuer, client_id: 'admin-console' } },
        operationId: 'account.consents.list',
        operationClass: 'read',
        outcome: 'succeeded',
        traceId: null,
      })
    );
    expect(appended).toMatchObject({ realmId: realm.id, seq: 1, actorId: admin.id });

    // It neither reads nor writes the log or its checkpoints itself.
    for (const statement of [
      'SELECT 1 FROM admin_audit_log',
      'SELECT 1 FROM admin_audit_log_checkpoints',
    ]) {
      expect(await sqlState(roleUser('api').query(statement)), statement).toBe(DENIED);
    }
    expect(
      await sqlState(
        roleUser('api').query(
          `INSERT INTO admin_audit_log (realm_id, seq, prev_hash, row_hash, actor_kind, actor_id,
             operation_id, operation_class, effects, outcome, approvals, created_at)
           VALUES ($1, 2, $2, $2, 'human_admin', $3, 'account.consents.list', 'read', '[]', 'succeeded', '[]', 0)`,
          [realm.id, appended.rowHash, admin.id]
        )
      )
    ).toBe(DENIED);
    // And no other role runs the functions.
    for (const role of DATABASE_ROLES.filter((role) => role !== 'api')) {
      expect(
        await sqlState(
          roleUser(role).query('SELECT * FROM admin_audit_act_chain_head($1::uuid)', [realm.id])
        ),
        role
      ).toBe(DENIED);
    }
  });

  it('lets every role keep its node in the list through the functions alone, and only its own (#499)', async () => {
    const node = {
      id: '00000000-0000-4000-8000-000000000499',
      roles: ['delivery'],
      digest: 'a'.repeat(64),
      keys: JSON.stringify({ JWT_ISSUER: 'b'.repeat(64) }),
    };
    const args = [node.id, node.roles, '0.3.0', node.digest, node.keys];
    try {
      // The table itself is no role's.
      for (const role of DATABASE_ROLES) {
        expect(await sqlState(roleUser(role).query('SELECT 1 FROM deployment_nodes')), role).toBe(
          '42501'
        );
      }
      expect(
        await sqlState(
          roleUser('web').query(
            `INSERT INTO deployment_nodes (node_id, roles, version, config_digest, config_keys, last_seen_at)
             VALUES (gen_random_uuid(), ARRAY['web'], '0.3.0', $1, '{}', 9000000000000000)`,
            [node.digest]
          )
        )
      ).toBe('42501');

      const { rows: registered } = await roleUser('delivery').query(
        'SELECT * FROM deployment_nodes_register($1::uuid, $2::text[], $3, $4, $5::jsonb, 120000)',
        args
      );
      expect(registered).toEqual([
        expect.objectContaining({ node_id: node.id, registered_by: USERS.delivery }),
      ]);
      const { rows: listed } = await roleUser('api').query(
        'SELECT node_id FROM deployment_nodes_live(120000)'
      );
      expect(listed).toEqual([{ node_id: node.id }]);

      // Another role's user neither marks it seen nor removes it.
      const heartbeat =
        'SELECT deployment_nodes_heartbeat($1::uuid, $2::text[], $3, $4, $5::jsonb, 0) AS seen';
      expect((await roleUser('web').query(heartbeat, args)).rows).toEqual([{ seen: null }]);
      expect(
        (
          await roleUser('web').query('SELECT deployment_nodes_remove($1::uuid) AS removed', [
            node.id,
          ])
        ).rows
      ).toEqual([{ removed: 0 }]);
      // Its own does.
      expect((await roleUser('delivery').query(heartbeat, args)).rows).toEqual([{ seen: 'seen' }]);
      expect(
        (
          await roleUser('delivery').query('SELECT deployment_nodes_remove($1::uuid) AS removed', [
            node.id,
          ])
        ).rows
      ).toEqual([{ removed: 1 }]);
      // A heartbeat writes a removed row again, never dated after now.
      expect(
        (
          await roleUser('delivery').query(
            'SELECT deployment_nodes_heartbeat($1::uuid, $2::text[], $3, $4, $5::jsonb, 9000000000000000) AS seen',
            args
          )
        ).rows
      ).toEqual([{ seen: 'restored' }]);
      const { rows: times } = await owner().query<{ future: boolean }>(
        `SELECT started_at > (extract(epoch FROM now()) * 1000)::bigint + 1000 AS future
           FROM deployment_nodes WHERE node_id = $1`,
        [node.id]
      );
      expect(times).toEqual([{ future: false }]);

      // A forged value is refused: an unknown role, a key digest that is none.
      expect(
        await sqlState(
          roleUser('web').query(
            'SELECT * FROM deployment_nodes_register(gen_random_uuid(), ARRAY[$1::text], $2, $3, $4::jsonb, 120000)',
            ['web\nset CONFIG_DIGEST_ROLLOUT', '0.3.0', node.digest, node.keys]
          )
        )
      ).toBe('23514');
      expect(
        await sqlState(
          roleUser('web').query(
            'SELECT * FROM deployment_nodes_register(gen_random_uuid(), ARRAY[$1::text], $2, $3, $4::jsonb, 120000)',
            ['web', '0.3.0', node.digest, JSON.stringify({ JWT_ISSUER: 'not a digest' })]
          )
        )
      ).toBe('23514');
    } finally {
      await owner().query('DELETE FROM deployment_nodes');
    }
  });
});
