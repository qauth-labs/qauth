/**
 * Real-Postgres integration tests for realm hosts and issuers (issue #470).
 *
 * The rules under test live in the DDL, so only a database can prove them:
 * `host` as the primary key across both kinds, the one-primary-per-realm
 * partial index, the one-operator-realm partial index, the CHECKs on the
 * stored forms, and the triggers that make a set issuer and a set primary host
 * permanent. The repository methods are exercised on top.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { BadRequestError, UniqueConstraintError } from '@qauth-labs/shared-errors';
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { InvalidRealmHostError } from '@qauth-labs/shared-validation';
import { eq } from 'drizzle-orm';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import { realmHosts, realms } from '../schema';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createRealmsRepository, type RealmsRepository } from './realms.repository';

describe('realm hosts and issuers integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let repo: RealmsRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    repo = createRealmsRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  function db(): IntegrationDb['database']['db'] {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.db;
  }

  function unique(prefix: string): string {
    return `${prefix}-${Math.random().toString(36).slice(2)}`;
  }

  /** A realm with an issuer on `host` and that host as its primary host. */
  async function realmOn(host: string): Promise<string> {
    const { realm } = await repo.createWithPrimaryHost(
      { name: unique('realm'), issuer: `https://${host}` },
      host
    );
    return realm.id;
  }

  /** A realm as a pre-0025 row looks: no issuer and no host. */
  async function bareRealm(): Promise<string> {
    const realm = await repo.create({ name: unique('bare') });
    return realm.id;
  }

  /** The Postgres error behind a rejected promise: `code` and `constraint`. */
  async function pgError(
    promise: Promise<unknown>
  ): Promise<{ code?: string; constraint?: string }> {
    try {
      await promise;
    } catch (error) {
      let current: unknown = error;
      while (current && typeof current === 'object') {
        const candidate = current as { code?: unknown; constraint?: unknown; cause?: unknown };
        if (typeof candidate.code === 'string' && /^[0-9A-Z]{5}$/.test(candidate.code)) {
          return { code: candidate.code, constraint: candidate.constraint as string | undefined };
        }
        current = candidate.cause;
      }
      throw error;
    }
    throw new Error('expected the statement to fail');
  }

  async function hostsOf(realmId: string): Promise<{ host: string; kind: string }[]> {
    const { rows } = await pool().query(
      `SELECT host, kind FROM realm_hosts WHERE realm_id = $1 ORDER BY host`,
      [realmId]
    );
    return rows;
  }

  describe('a host belongs to one realm, across both kinds', () => {
    it('refuses the same primary host in two realms, in any spelling', async () => {
      await realmOn('auth.example.com');

      for (const spelling of ['auth.example.com', 'AUTH.Example.com', 'auth.example.com.']) {
        const second = repo.createWithPrimaryHost(
          { name: unique('second'), issuer: `https://${spelling}:8443` },
          `${spelling}:8443`
        );
        await expect(second).rejects.toBeInstanceOf(UniqueConstraintError);
        await expect(second).rejects.toMatchObject({ constraint: 'realm_hosts_pkey' });
      }
    });

    it('rolls the realm back when its primary host is taken', async () => {
      await realmOn('auth.example.com');
      const name = unique('loser');

      // Another issuer string, so the realm row itself goes in and only the
      // host insert fails.
      await expect(
        repo.createWithPrimaryHost({ name, issuer: 'https://AUTH.example.com' }, 'auth.example.com')
      ).rejects.toMatchObject({ constraint: 'realm_hosts_pkey' });
      expect(await repo.findByName(name)).toBeUndefined();
    });

    it("refuses one realm's primary host as another realm's endpoint host", async () => {
      await realmOn('auth.example.com');
      const other = await realmOn('other.example.com');

      const endpoint = repo.addEndpointHost(other, 'Auth.Example.com:3000');
      await expect(endpoint).rejects.toBeInstanceOf(UniqueConstraintError);
      await expect(endpoint).rejects.toMatchObject({ constraint: 'realm_hosts_pkey' });
    });

    it("refuses one realm's endpoint host as another realm's primary host", async () => {
      const first = await realmOn('auth.example.com');
      await repo.addEndpointHost(first, 'internal.example.com');

      await expect(
        repo.createWithPrimaryHost(
          { name: unique('second'), issuer: 'https://internal.example.com' },
          'internal.example.com'
        )
      ).rejects.toMatchObject({ constraint: 'realm_hosts_pkey' });
    });

    it('refuses one endpoint host in two realms, and twice in one realm', async () => {
      const first = await realmOn('a.example.com');
      const second = await realmOn('b.example.com');
      await repo.addEndpointHost(first, 'auth-server');

      await expect(repo.addEndpointHost(second, 'AUTH-SERVER')).rejects.toBeInstanceOf(
        UniqueConstraintError
      );
      await expect(repo.addEndpointHost(first, 'auth-server:3000')).rejects.toBeInstanceOf(
        UniqueConstraintError
      );
    });
  });

  describe('one primary host per realm', () => {
    it('refuses a second primary host for one realm', async () => {
      const realmId = await realmOn('auth.example.com');

      await expect(
        pgError(
          pool().query(
            `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ($1, $2, 'primary')`,
            ['second.example.com', realmId]
          )
        )
      ).resolves.toEqual({ code: '23505', constraint: 'idx_realm_hosts_one_primary' });
    });

    it('refuses to promote an endpoint host of a realm that has a primary host', async () => {
      const realmId = await realmOn('auth.example.com');
      await repo.addEndpointHost(realmId, 'auth-server');

      await expect(
        pgError(pool().query(`UPDATE realm_hosts SET kind = 'primary' WHERE host = 'auth-server'`))
      ).resolves.toEqual({ code: '23505', constraint: 'idx_realm_hosts_one_primary' });
    });

    it('lets a realm without a primary host take one, once', async () => {
      const realmId = await bareRealm();

      await db().insert(realmHosts).values({ host: 'late.example.com', realmId, kind: 'primary' });
      expect(await hostsOf(realmId)).toEqual([{ host: 'late.example.com', kind: 'primary' }]);

      await expect(
        pgError(
          pool().query(
            `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ('later.example.com', $1, 'primary')`,
            [realmId]
          )
        )
      ).resolves.toEqual({ code: '23505', constraint: 'idx_realm_hosts_one_primary' });
    });
  });

  describe('a set primary host is permanent', () => {
    it('refuses to change its host, its realm or its kind', async () => {
      const realmId = await realmOn('auth.example.com');
      const other = await bareRealm();
      const permanent = { code: '23514', constraint: 'realm_hosts_primary_permanent' };

      await expect(
        pgError(
          pool().query(
            `UPDATE realm_hosts SET host = 'moved.example.com' WHERE host = 'auth.example.com'`
          )
        )
      ).resolves.toEqual(permanent);
      await expect(
        pgError(
          pool().query(`UPDATE realm_hosts SET realm_id = $1 WHERE host = 'auth.example.com'`, [
            other,
          ])
        )
      ).resolves.toEqual(permanent);
      await expect(
        pgError(
          pool().query(`UPDATE realm_hosts SET kind = 'endpoint' WHERE host = 'auth.example.com'`)
        )
      ).resolves.toEqual(permanent);

      expect(await hostsOf(realmId)).toEqual([{ host: 'auth.example.com', kind: 'primary' }]);
    });

    it('refuses to delete it while the realm exists', async () => {
      const realmId = await realmOn('auth.example.com');

      await expect(
        pgError(pool().query(`DELETE FROM realm_hosts WHERE host = 'auth.example.com'`))
      ).resolves.toEqual({ code: '23514', constraint: 'realm_hosts_primary_permanent' });
      expect(await hostsOf(realmId)).toEqual([{ host: 'auth.example.com', kind: 'primary' }]);
    });

    it('allows an UPDATE that changes none of its identity', async () => {
      const realmId = await realmOn('auth.example.com');

      await pool().query(
        `UPDATE realm_hosts SET host = host, created_at = 1 WHERE host = 'auth.example.com'`
      );
      expect(await hostsOf(realmId)).toEqual([{ host: 'auth.example.com', kind: 'primary' }]);
    });

    it('goes with its realm when the realm is deleted', async () => {
      const realmId = await realmOn('auth.example.com');
      await repo.addEndpointHost(realmId, 'auth-server');

      expect(await repo.delete(realmId)).toBe(true);
      expect(await hostsOf(realmId)).toEqual([]);
      // The host is free again once its realm is gone.
      await expect(realmOn('auth.example.com')).resolves.toEqual(expect.any(String));
    });

    it('lets endpoint hosts change and go', async () => {
      const realmId = await realmOn('auth.example.com');
      const other = await realmOn('other.example.com');
      await repo.addEndpointHost(realmId, 'auth-server');

      await pool().query(`UPDATE realm_hosts SET realm_id = $1 WHERE host = 'auth-server'`, [
        other,
      ]);
      expect(await hostsOf(other)).toContainEqual({ host: 'auth-server', kind: 'endpoint' });
      await pool().query(`DELETE FROM realm_hosts WHERE host = 'auth-server'`);
      expect(await hostsOf(other)).toEqual([{ host: 'other.example.com', kind: 'primary' }]);
    });
  });

  describe('a set issuer is permanent', () => {
    it('can be set once from NULL', async () => {
      const realmId = await bareRealm();

      const updated = await repo.update(realmId, { issuer: 'https://auth.example.com' });
      expect(updated.issuer).toBe('https://auth.example.com');
    });

    it('refuses any change once set, to another value or back to NULL', async () => {
      const realmId = await realmOn('auth.example.com');
      const permanent = { code: '23514', constraint: 'realms_issuer_permanent' };

      await expect(
        pgError(repo.update(realmId, { issuer: 'https://other.example.com' }))
      ).resolves.toEqual(permanent);
      await expect(pgError(repo.update(realmId, { issuer: null }))).resolves.toEqual(permanent);
      await expect(
        pgError(pool().query(`UPDATE realms SET issuer = issuer || '/x' WHERE id = $1`, [realmId]))
      ).resolves.toEqual(permanent);

      expect((await repo.findById(realmId))?.issuer).toBe('https://auth.example.com');
    });

    it('allows every other update of the realm, and writing the same issuer again', async () => {
      const realmId = await realmOn('auth.example.com');

      const renamed = await repo.update(realmId, {
        name: unique('renamed'),
        enabled: false,
        issuer: 'https://auth.example.com',
      });
      expect(renamed).toMatchObject({ enabled: false, issuer: 'https://auth.example.com' });
    });

    it('is unique across realms', async () => {
      await realmOn('auth.example.com');
      const bare = await bareRealm();

      await expect(repo.update(bare, { issuer: 'https://auth.example.com' })).rejects.toMatchObject(
        { constraint: 'realms_issuer_unique' }
      );
    });

    it('refuses an empty issuer and one with a trailing slash', async () => {
      const realmId = await bareRealm();

      await expect(pgError(repo.update(realmId, { issuer: '' }))).resolves.toEqual({
        code: '23514',
        constraint: 'realms_issuer_not_empty',
      });
      await expect(
        pgError(repo.update(realmId, { issuer: 'https://auth.example.com/' }))
      ).resolves.toEqual({ code: '23514', constraint: 'realms_issuer_no_trailing_slash' });
    });

    it('refuses plain http off localhost, and white space, control characters or a backslash', async () => {
      const realmId = await bareRealm();
      const cases: Array<[string, string]> = [
        ['http://auth.example.com', 'realms_issuer_scheme'],
        ['ftp://auth.example.com', 'realms_issuer_scheme'],
        ['http://localhost.example.com', 'realms_issuer_scheme'],
        ['https://auth.example.com/ ', 'realms_issuer_no_space_or_control'],
        ['https://auth.example.com\n', 'realms_issuer_no_space_or_control'],
        ['https://auth.example.com/a\tb', 'realms_issuer_no_space_or_control'],
        ['https://auth.example.com\\auth', 'realms_issuer_no_space_or_control'],
      ];
      for (const [issuer, constraint] of cases) {
        await expect(pgError(repo.update(realmId, { issuer }))).resolves.toEqual({
          code: '23514',
          constraint,
        });
      }

      const dev = `http://${unique('dev')}.localhost:3000`;
      await expect(repo.update(realmId, { issuer: dev })).resolves.toMatchObject({ issuer: dev });
    });
  });

  describe('one operator realm', () => {
    it('refuses a second realm with is_operator = true', async () => {
      const first = await bareRealm();
      const second = await bareRealm();
      await repo.update(first, { isOperator: true });

      const promoted = repo.update(second, { isOperator: true });
      await expect(promoted).rejects.toBeInstanceOf(UniqueConstraintError);
      await expect(promoted).rejects.toMatchObject({ constraint: 'idx_realms_one_operator' });
      await expect(
        pgError(pool().query(`INSERT INTO realms (name, is_operator) VALUES ('third', true)`))
      ).resolves.toEqual({ code: '23505', constraint: 'idx_realms_one_operator' });
    });

    it('allows any number of non-operator realms, and moving the flag', async () => {
      const first = await bareRealm();
      const second = await bareRealm();
      await bareRealm();
      await repo.update(first, { isOperator: true });

      await db().transaction(async (tx) => {
        await repo.update(first, { isOperator: false }, tx);
        await repo.update(second, { isOperator: true }, tx);
      });
      const { rows } = await pool().query(`SELECT id FROM realms WHERE is_operator`);
      expect(rows).toEqual([{ id: second }]);
    });

    it('defaults to false', async () => {
      const realmId = await bareRealm();
      expect((await repo.findById(realmId))?.isOperator).toBe(false);
    });
  });

  describe('the stored host form', () => {
    it('refuses a host that is not in normalised form', async () => {
      const realmId = await bareRealm();
      for (const host of [
        'Auth.example.com',
        'auth.example.com.',
        'auth.example.com:443',
        '*.example.com',
        'auth..example.com',
        'bücher.example',
        'auth example.com',
        '',
      ]) {
        await expect(
          pgError(
            pool().query(
              `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ($1, $2, 'endpoint')`,
              [host, realmId]
            )
          )
        ).resolves.toEqual({ code: '23514', constraint: 'realm_hosts_host_normalised' });
      }
    });

    it('refuses an IP literal as a primary host and accepts it as an endpoint host', async () => {
      const realmId = await bareRealm();
      for (const host of ['192.0.2.10', '[::1]']) {
        await expect(
          pgError(
            pool().query(
              `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ($1, $2, 'primary')`,
              [host, realmId]
            )
          )
        ).resolves.toEqual({ code: '23514', constraint: 'realm_hosts_primary_not_ip_literal' });
        await pool().query(
          `INSERT INTO realm_hosts (host, realm_id, kind) VALUES ($1, $2, 'endpoint')`,
          [host, realmId]
        );
      }
    });
  });

  describe('repository', () => {
    it('createWithPrimaryHost stores the normalised host and the issuer as given', async () => {
      const { realm, host } = await repo.createWithPrimaryHost(
        { name: unique('idn'), issuer: 'https://Bücher.example:8443' },
        'BÜCHER.example.:8443'
      );

      expect(realm.issuer).toBe('https://Bücher.example:8443');
      expect(host).toMatchObject({
        host: 'xn--bcher-kva.example',
        realmId: realm.id,
        kind: 'primary',
      });
    });

    it('createWithPrimaryHost refuses an IP literal before it writes anything', async () => {
      const name = unique('ip');
      await expect(
        repo.createWithPrimaryHost({ name, issuer: 'https://192.0.2.10' }, '192.0.2.10')
      ).rejects.toMatchObject({ reason: 'ip_literal' });
      expect(await repo.findByName(name)).toBeUndefined();
    });

    it('createWithPrimaryHost refuses an issuer that is not on the primary host', async () => {
      const cases = [
        'https://other.example.com',
        'https://auth.example.com/',
        'https://auth.example.com?tenant=a',
        'https://auth.example.com#x',
        'https://user@auth.example.com',
        'https://user:secret@auth.example.com',
        'auth.example.com',
      ];
      for (const issuer of cases) {
        await expect(
          repo.createWithPrimaryHost({ name: unique('bad'), issuer }, 'auth.example.com')
        ).rejects.toBeInstanceOf(BadRequestError);
      }
      // A port or a path on the issuer is fine: only its host must match.
      await expect(
        repo.createWithPrimaryHost(
          { name: unique('ok'), issuer: 'https://AUTH.example.com:8443/auth' },
          'auth.example.com'
        )
      ).resolves.toMatchObject({ host: { host: 'auth.example.com' } });
    });

    it('createWithPrimaryHost refuses plain http off localhost, white space, control characters and a backslash', async () => {
      const cases = [
        'http://auth.example.com',
        'http://auth.example.com:8080/auth',
        ' https://auth.example.com',
        'https://auth.example.com/ ',
        'https://auth.example.com\n',
        'https://auth.example.com/a\tb',
        'https://auth.example.com/\u007f',
        'https://auth.example.com\\auth',
      ];
      for (const issuer of cases) {
        const name = unique('bad');
        await expect(
          repo.createWithPrimaryHost({ name, issuer }, 'auth.example.com')
        ).rejects.toBeInstanceOf(BadRequestError);
        expect(await repo.findByName(name)).toBeUndefined();
      }

      // Development: plain http on localhost or a name under it.
      const host = `${unique('dev')}.localhost`;
      await expect(
        repo.createWithPrimaryHost({ name: unique('dev'), issuer: `http://${host}:3000` }, host)
      ).resolves.toMatchObject({ host: { host } });
    });

    it('createWithPrimaryHost joins an outer transaction and rolls back with it', async () => {
      const name = unique('outer');
      await expect(
        db().transaction(async (tx) => {
          await repo.createWithPrimaryHost(
            { name, issuer: 'https://outer.example.com' },
            'outer.example.com',
            tx
          );
          throw new Error('abort');
        })
      ).rejects.toThrow('abort');
      expect(await repo.findByName(name)).toBeUndefined();
      expect(await repo.findByHost('outer.example.com')).toBeUndefined();
    });

    it('findByHost resolves every spelling of a primary or endpoint host to its realm', async () => {
      const realmId = await realmOn('auth.example.com');
      await repo.addEndpointHost(realmId, 'auth-server');
      await repo.addEndpointHost(realmId, '[::1]');

      for (const spelling of ['auth.example.com', 'AUTH.Example.com:8443', 'auth.example.com.']) {
        await expect(repo.findByHost(spelling)).resolves.toMatchObject({
          realm: { id: realmId, issuer: 'https://auth.example.com' },
          host: { host: 'auth.example.com', kind: 'primary' },
        });
      }
      await expect(repo.findByHost('auth-server:3000')).resolves.toMatchObject({
        realm: { id: realmId },
        host: { host: 'auth-server', kind: 'endpoint' },
      });
      await expect(repo.findByHost('[0:0::1]:3000')).resolves.toMatchObject({
        host: { host: '[::1]', kind: 'endpoint' },
      });
    });

    it('findByHost returns nothing for an unknown host or a value that is not a host', async () => {
      await realmOn('auth.example.com');

      await expect(repo.findByHost('unknown.example.com')).resolves.toBeUndefined();
      await expect(repo.findByHost('*.example.com')).resolves.toBeUndefined();
      await expect(repo.findByHost('auth.example.com/x')).resolves.toBeUndefined();
      await expect(repo.findByHost('')).resolves.toBeUndefined();
    });

    it('findByHost returns a disabled realm and leaves the refusal to the caller', async () => {
      const realmId = await realmOn('auth.example.com');
      await repo.update(realmId, { enabled: false });

      await expect(repo.findByHost('auth.example.com')).resolves.toMatchObject({
        realm: { id: realmId, enabled: false },
      });
    });

    it('addEndpointHost accepts an IP literal and refuses a wildcard', async () => {
      const realmId = await realmOn('auth.example.com');

      await expect(repo.addEndpointHost(realmId, '10.0.0.5:3000')).resolves.toMatchObject({
        host: '10.0.0.5',
        kind: 'endpoint',
      });
      await expect(repo.addEndpointHost(realmId, '*.internal')).rejects.toBeInstanceOf(
        InvalidRealmHostError
      );
    });

    it('removeEndpointHost removes an endpoint host of that realm only', async () => {
      const realmId = await realmOn('auth.example.com');
      const other = await realmOn('other.example.com');
      await repo.addEndpointHost(realmId, 'auth-server');

      await expect(repo.removeEndpointHost(other, 'auth-server')).resolves.toBe(false);
      await expect(repo.removeEndpointHost(realmId, 'AUTH-SERVER:3000')).resolves.toBe(true);
      await expect(repo.removeEndpointHost(realmId, 'auth-server')).resolves.toBe(false);
      expect(await hostsOf(realmId)).toEqual([{ host: 'auth.example.com', kind: 'primary' }]);
    });

    it('removeEndpointHost never removes a primary host', async () => {
      const realmId = await realmOn('auth.example.com');

      await expect(repo.removeEndpointHost(realmId, 'auth.example.com')).resolves.toBe(false);
      await expect(repo.removeEndpointHost(realmId, '*')).resolves.toBe(false);
      const [row] = await db()
        .select()
        .from(realmHosts)
        .where(eq(realmHosts.host, 'auth.example.com'));
      expect(row).toMatchObject({ realmId, kind: 'primary' });
    });

    it('create still makes a realm with no issuer and no host, as before', async () => {
      const realmId = await bareRealm();
      const [row] = await db().select().from(realms).where(eq(realms.id, realmId));
      expect(row).toMatchObject({ issuer: null, isOperator: false });
      expect(await hostsOf(realmId)).toEqual([]);
    });
  });
});
