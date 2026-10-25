import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { defaultRealmPlugin, type DefaultRealmPluginOptions } from './plugins/default-realm';

/**
 * THE DEFAULT REALM'S BOOT STEP AGAINST A REAL POSTGRES (ADR-019 Decision 1,
 * issue #484).
 *
 * Each "node" is a Fastify instance with its own pool, the database plugin and
 * the default realm plugin, booted with `ready()` as `listen()` boots it. What
 * only a database can show: the realm the step creates or fills, the refusal
 * when the stored issuer differs from `JWT_ISSUER`, nodes booting at once
 * creating one realm under the advisory lock, and endpoint hosts that are added
 * and never removed. One test boots the real auth-server to show `app()` runs
 * the step.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const ISSUER = 'https://auth.example.com';

interface LogLine {
  readonly msg: string;
  readonly level: number;
  readonly [field: string]: unknown;
}

interface Node {
  readonly app: FastifyInstance;
  readonly lines: LogLine[];
}

describe('default realm boot step on a real Postgres', () => {
  let infra: E2eInfrastructure | undefined;
  let admin: FastifyInstance | undefined;
  let dockerUp = false;
  const nodes: Node[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    admin = Fastify({ logger: false });
    await admin.register(databasePlugin, {
      config: { connectionString: infra.postgres.connectionString },
    });
    await admin.ready();
  }, 240_000);

  afterAll(async () => {
    await admin?.close();
    await infra?.teardown();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await database().dbPool.query(truncateDomainTablesStatement());
  });

  afterEach(async () => {
    await Promise.all(nodes.splice(0).map((node) => node.app.close()));
  });

  function database(): FastifyInstance {
    if (!admin) throw new Error('database not started');
    return admin;
  }

  function realms(): FastifyInstance['repositories']['realms'] {
    return database().repositories.realms;
  }

  /**
   * Boot a node with the given settings, the defaults being the single-realm
   * settings of a fresh deployment. Rejects with the boot step's error.
   */
  async function bootNode(settings: Partial<DefaultRealmPluginOptions> = {}): Promise<Node> {
    if (!infra) throw new Error('database not started');
    const lines: LogLine[] = [];
    const app = Fastify({
      logger: {
        level: 'info',
        stream: {
          write(chunk: string) {
            lines.push(JSON.parse(chunk) as LogLine);
          },
        },
      },
    });
    const node = { app, lines };
    nodes.push(node);
    await app.register(databasePlugin, {
      config: { connectionString: infra.postgres.connectionString, pool: { max: 2, min: 0 } },
    });
    await app.register(defaultRealmPlugin, {
      realmName: 'master',
      jwtIssuer: ISSUER,
      endpointHosts: [],
      ...settings,
    });
    await app.ready();
    return node;
  }

  /** The node's one "default realm ready" line. */
  function readyLine(node: Node): LogLine {
    const lines = node.lines.filter((line) => line.msg === 'default realm ready');
    expect(lines).toHaveLength(1);
    return lines[0];
  }

  async function hostsOf(realmId: string): Promise<{ host: string; kind: string }[]> {
    const { rows } = await database().dbPool.query<{ host: string; kind: string }>(
      'SELECT host, kind FROM realm_hosts WHERE realm_id = $1 ORDER BY host',
      [realmId]
    );
    return rows;
  }

  async function realmCount(): Promise<number> {
    const { rows } = await database().dbPool.query<{ count: string }>(
      'SELECT count(*) FROM realms'
    );
    return Number(rows[0].count);
  }

  describe('the realm and its issuer', () => {
    it('boots an empty database with the realm DEFAULT_REALM_NAME names, its issuer and host from JWT_ISSUER, flagged operator', async () => {
      const node = await bootNode();

      const realm = await realms().findByName('master');
      expect(realm).toMatchObject({ issuer: ISSUER, isOperator: true, enabled: true });
      expect(await hostsOf(realm?.id ?? '')).toEqual([
        { host: 'auth.example.com', kind: 'primary' },
      ]);
      expect(readyLine(node)).toMatchObject({
        realm: 'master',
        issuer: ISSUER,
        host: 'auth.example.com',
        operator: true,
      });
    });

    it('fills a realm that has no issuer, and leaves its users and clients as they were', async () => {
      const bare = await realms().create({ name: 'master', enabled: true });
      const pool = database().dbPool;
      await pool.query(
        `INSERT INTO users (realm_id, first_name) VALUES ($1, 'Ada'), ($1, 'Grace')`,
        [bare.id]
      );
      await pool.query(
        `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris)
         VALUES ($1, 'portal', 'hash', 'Portal', '["https://portal.example.com/cb"]')`,
        [bare.id]
      );
      const snapshot = async () => ({
        users: (await pool.query('SELECT * FROM users ORDER BY id')).rows,
        clients: (await pool.query('SELECT * FROM oauth_clients ORDER BY id')).rows,
      });
      const before = await snapshot();

      await bootNode();

      expect(await snapshot()).toEqual(before);
      expect(await realms().findByName('master')).toMatchObject({
        id: bare.id,
        issuer: ISSUER,
        isOperator: true,
      });
      expect(await hostsOf(bare.id)).toEqual([{ host: 'auth.example.com', kind: 'primary' }]);
      expect(await realmCount()).toBe(1);
    });

    it('refuses to boot when the stored issuer differs from JWT_ISSUER, naming both values', async () => {
      await bootNode();

      await expect(bootNode({ jwtIssuer: 'https://login.example.com' })).rejects.toThrow(
        'The default realm "master" has the issuer "https://auth.example.com", but JWT_ISSUER is "https://login.example.com".'
      );
      const realm = await realms().findByName('master');
      expect(realm?.issuer).toBe(ISSUER);
      expect(await realms().findByHost('login.example.com')).toBeUndefined();
    });

    it('stores a JWT_ISSUER with a trailing slash without it, and boots again with or without it', async () => {
      const node = await bootNode({ jwtIssuer: 'https://auth.example.com:8443/' });

      const realm = await realms().findByName('master');
      expect(realm?.issuer).toBe('https://auth.example.com:8443');
      expect(await hostsOf(realm?.id ?? '')).toEqual([
        { host: 'auth.example.com', kind: 'primary' },
      ]);
      expect(node.lines.filter((line) => line.level === 40)).toHaveLength(1);

      await expect(bootNode({ jwtIssuer: 'https://auth.example.com:8443' })).resolves.toBeDefined();
      await expect(
        bootNode({ jwtIssuer: 'https://auth.example.com:8443/' })
      ).resolves.toBeDefined();
    });

    it('stores a JWT_ISSUER with a path as it is, on its host', async () => {
      await bootNode({ jwtIssuer: 'https://example.com/auth' });

      const realm = await realms().findByName('master');
      expect(realm?.issuer).toBe('https://example.com/auth');
      expect(await hostsOf(realm?.id ?? '')).toEqual([{ host: 'example.com', kind: 'primary' }]);
    });

    it("refuses a JWT_ISSUER whose host is another realm's, naming the host and that realm", async () => {
      await realms().createWithPrimaryHost(
        { name: 'tenant', issuer: 'https://auth.example.com/tenant' },
        'auth.example.com'
      );

      await expect(bootNode()).rejects.toThrow(
        'The host "auth.example.com" of JWT_ISSUER "https://auth.example.com" is already the primary host of the realm "tenant".'
      );
      expect(await realms().findByName('master')).toBeUndefined();
    });

    it('refuses plain http off localhost, which no realm issuer may use, and writes nothing', async () => {
      await expect(bootNode({ jwtIssuer: 'http://auth.example.com' })).rejects.toThrow(
        'JWT_ISSUER "http://auth.example.com" cannot be the issuer of the default realm "master": Realm issuer must use https'
      );
      expect(await realmCount()).toBe(0);
    });
  });

  describe('the operator realm', () => {
    it('leaves the flag on another realm that already holds it', async () => {
      const tenant = await realms().createWithPrimaryHost(
        { name: 'operator', issuer: 'https://admin.example.com' },
        'admin.example.com'
      );
      await realms().update(tenant.realm.id, { isOperator: true });

      const node = await bootNode();

      expect(await realms().findByName('master')).toMatchObject({ isOperator: false });
      expect(await realms().findOperator()).toMatchObject({ id: tenant.realm.id });
      expect(readyLine(node)).toMatchObject({ realm: 'master', operator: false });
    });
  });

  describe('nodes that boot together', () => {
    it('create one realm, one primary host and one operator', async () => {
      const booted = await Promise.allSettled(
        Array.from({ length: 4 }, () => bootNode({ endpointHosts: ['auth-server'] }))
      );

      expect(booted.map((result) => result.status)).toEqual(Array(4).fill('fulfilled'));
      expect(await realmCount()).toBe(1);
      const realm = await realms().findByName('master');
      expect(realm).toMatchObject({ issuer: ISSUER, isOperator: true });
      expect(await hostsOf(realm?.id ?? '')).toEqual([
        { host: 'auth-server', kind: 'endpoint' },
        { host: 'auth.example.com', kind: 'primary' },
      ]);
      // Under the lock the steps ran one after another: one node added the
      // endpoint host, and every later one found it.
      const added = nodes.map((node) => readyLine(node)['endpointHostsAdded']);
      expect(added.filter((hosts) => (hosts as string[]).length > 0)).toEqual([['auth-server']]);
    });
  });

  describe('DEFAULT_REALM_ENDPOINT_HOSTS', () => {
    it('stores auth-server as an endpoint host of the default realm', async () => {
      await bootNode({ endpointHosts: ['auth-server'] });

      expect(await realms().findByHost('auth-server')).toMatchObject({
        realm: { name: 'master' },
        host: { host: 'auth-server', kind: 'endpoint' },
      });
    });

    it('removes nothing when a later boot has a shorter list', async () => {
      await bootNode({ endpointHosts: ['auth-server', 'portal-backend', '10.0.0.5'] });
      const realm = await realms().findByName('master');
      const stored = await hostsOf(realm?.id ?? '');
      expect(stored).toHaveLength(4);

      const shorter = await bootNode({ endpointHosts: ['auth-server'] });
      await bootNode({ endpointHosts: [] });

      expect(await hostsOf(realm?.id ?? '')).toEqual(stored);
      expect(readyLine(shorter)).toMatchObject({ endpointHostsAdded: [] });
    });

    it('refuses a host another realm has, naming the host and that realm, and writes nothing', async () => {
      const tenant = await realms().createWithPrimaryHost(
        { name: 'tenant', issuer: 'https://tenant.example.com' },
        'tenant.example.com'
      );
      await realms().addEndpointHost(tenant.realm.id, 'tenant-internal');

      await expect(bootNode({ endpointHosts: ['tenant-internal'] })).rejects.toThrow(
        'DEFAULT_REALM_ENDPOINT_HOSTS names "tenant-internal", which is already an endpoint host of the realm "tenant".'
      );
      await expect(bootNode({ endpointHosts: ['tenant.example.com'] })).rejects.toThrow(
        'DEFAULT_REALM_ENDPOINT_HOSTS names "tenant.example.com", which is already the primary host of the realm "tenant".'
      );
      // The whole step is one transaction: the realm it was creating is gone too.
      expect(await realms().findByName('master')).toBeUndefined();
    });

    it("refuses the default realm's own primary host", async () => {
      await expect(bootNode({ endpointHosts: ['auth.example.com'] })).rejects.toThrow(
        'DEFAULT_REALM_ENDPOINT_HOSTS names "auth.example.com", the primary host of the default realm "master"'
      );
    });
  });

  describe('the auth-server', () => {
    it('runs the step when it boots: an empty database gets the default realm', async () => {
      if (!infra) throw new Error('database not started');
      const server = await bootAuthServer({
        ...baseEnvironment(infra, await generateJwtPem()),
        DEFAULT_REALM_ENDPOINT_HOSTS: 'auth-server',
      });
      try {
        const realm = await server.app.repositories.realms.findByName('master');
        expect(realm).toMatchObject({ issuer: ISSUER, isOperator: true });
        expect(await hostsOf(realm?.id ?? '')).toEqual([
          { host: 'auth-server', kind: 'endpoint' },
          { host: 'auth.example.com', kind: 'primary' },
        ]);
      } finally {
        await server.close();
      }
    });

    it('seeds the new realm with the event retention keys, and a later boot changes nothing (#536)', async () => {
      if (!infra) throw new Error('database not started');
      const environment = baseEnvironment(infra, await generateJwtPem());
      const first = await bootAuthServer({
        ...environment,
        EVENT_RETENTION_USER_DAYS: '30',
        EVENT_RETENTION_ADMIN_DAYS: '120',
      });
      try {
        expect(await first.app.repositories.realms.findByName('master')).toMatchObject({
          userEventRetentionDays: 30,
          adminEventRetentionDays: 120,
        });
      } finally {
        await first.close();
      }

      // The realm row owns the policy once the realm exists (ADR-019 Decision 10).
      const second = await bootAuthServer({
        ...environment,
        EVENT_RETENTION_USER_DAYS: '60',
        EVENT_RETENTION_ADMIN_DAYS: '200',
      });
      try {
        expect(await second.app.repositories.realms.findByName('master')).toMatchObject({
          userEventRetentionDays: 30,
          adminEventRetentionDays: 120,
        });
      } finally {
        await second.close();
      }
    });
  });
});
