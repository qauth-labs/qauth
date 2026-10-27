import cors from '@fastify/cors';
import Fastify, { type FastifyInstance, type FastifyServerOptions } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

// The error handler reads the validated env; only NODE_ENV matters to it.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));

import type { RealmHostLookup, RealmHostMatch } from '../helpers/realm-host-cache';
import type { RouteSurface } from '../helpers/route-surface';
import errorHandler from './error-handler';
import { realmResolverPlugin, type RealmResolverPluginOptions } from './realm-resolver';

/**
 * The realm resolver (#486) in a bare Fastify instance: the plugin, the app's
 * error handler, a host table in memory and one echo route per surface. What a
 * real `realm_hosts` table adds is covered by `realm-resolver.integration.test.ts`.
 */

interface RealmSpec {
  readonly name: string;
  readonly enabled?: boolean;
  readonly issuer?: string | null;
}

/** An in-memory `realm_hosts`, keyed by the stored (normalised) host. */
function hostTable() {
  const rows = new Map<string, RealmHostMatch>();
  const add = (host: string, kind: 'primary' | 'endpoint', realm: RealmSpec) => {
    rows.set(host, {
      realm: {
        id: `id-${realm.name}`,
        name: realm.name,
        enabled: realm.enabled ?? true,
        issuer: realm.issuer === undefined ? `https://${realm.name}.example.com` : realm.issuer,
      },
      host: { host, realmId: `id-${realm.name}`, kind, createdAt: 0 },
    } as RealmHostMatch);
  };
  const lookup = vi.fn<RealmHostLookup>(async (host) => rows.get(host));
  return { rows, add, lookup };
}

/** The table most tests use: realm A on two hosts, realm B, and two refused realms. */
function standardTable() {
  const table = hostTable();
  table.add('auth.example.com', 'primary', { name: 'a' });
  table.add('auth-server', 'endpoint', { name: 'a' });
  table.add('xn--bcher-kva.example', 'primary', { name: 'idn' });
  table.add('b.example.com', 'primary', { name: 'b' });
  table.add('off.example.com', 'primary', { name: 'off', enabled: false });
  table.add('legacy-internal', 'endpoint', { name: 'legacy', issuer: null });
  return table;
}

/** Answers with what the resolver put on the request, and sets a cookie to prove it ran. */
async function echo(request: { realm: RealmHostMatch['realm'] | null; realmHost: unknown }) {
  return { realm: request.realm?.name ?? null, realmHost: request.realmHost };
}

async function build(
  lookup: RealmHostLookup,
  options: Omit<RealmResolverPluginOptions, 'lookup'> = {},
  serverOptions: FastifyServerOptions = {}
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false, ...serverOptions });
  await app.register(realmResolverPlugin, { lookup, ...options });
  await app.register(errorHandler);
  const surfaces: RouteSurface[] = ['browser', 'api', 'meta', 'none'];
  for (const surface of surfaces) {
    app.get(`/${surface}`, { config: { surface } }, async (request, reply) => {
      reply.header('set-cookie', '__Host-qauth_session=reached; Path=/; Secure; HttpOnly');
      return echo(request);
    });
  }
  await app.ready();
  return app;
}

describe('realm resolver plugin (#486)', () => {
  describe('matching the request host', () => {
    it.each(['auth.example.com', 'AUTH.Example.com', 'auth.example.com:8443', 'auth.example.com.'])(
      'resolves %s to realm A',
      async (host) => {
        const table = standardTable();
        const app = await build(table.lookup);

        const response = await app.inject({ method: 'GET', url: '/api', headers: { host } });

        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({
          realm: 'a',
          realmHost: { host: 'auth.example.com', kind: 'primary' },
        });
        expect(table.lookup).toHaveBeenCalledWith('auth.example.com');
        await app.close();
      }
    );

    it.each(['xn--bcher-kva.example', 'bücher.example', 'BÜCHER.example:443', 'Bücher.example.'])(
      'resolves %s, a spelling of the punycode host, to the same realm',
      async (host) => {
        const table = standardTable();
        const app = await build(table.lookup);

        const response = await app.inject({ method: 'GET', url: '/api', headers: { host } });

        expect(response.statusCode).toBe(200);
        expect(response.json()).toMatchObject({ realm: 'idn' });
        expect(table.lookup).toHaveBeenCalledWith('xn--bcher-kva.example');
        await app.close();
      }
    );

    it('gives realm B on its own host', async () => {
      const app = await build(standardTable().lookup);

      const response = await app.inject({
        method: 'GET',
        url: '/api',
        headers: { host: 'b.example.com' },
      });

      expect(response.json()).toEqual({
        realm: 'b',
        realmHost: { host: 'b.example.com', kind: 'primary' },
      });
      await app.close();
    });
  });

  describe('refusing with 421', () => {
    it.each([
      ['an unknown host', 'unknown.example'],
      ['a disabled realm', 'off.example.com'],
      ['a realm with no issuer', 'legacy-internal'],
    ])('refuses %s with no cookie and no realm data', async (_case, host) => {
      const app = await build(standardTable().lookup);

      for (const surface of ['browser', 'api', 'meta']) {
        const response = await app.inject({ method: 'GET', url: `/${surface}`, headers: { host } });

        expect(response.statusCode).toBe(421);
        expect(response.headers['set-cookie']).toBeUndefined();
        expect(response.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
        const body = response.json() as Record<string, unknown>;
        expect(body).toMatchObject({ status: 421, code: 'misdirected_request' });
        // The problem document's own members and nothing else: no realm data.
        expect(Object.keys(body).sort()).toEqual([
          'code',
          'detail',
          'instance',
          'status',
          'title',
          'trace_id',
          'type',
        ]);
      }
      await app.close();
    });

    // An empty Host cannot be injected: light-my-request replaces it with its own.
    it.each(['*.example.com', 'auth.example.com:99999', 'auth..example.com', 'a/b'])(
      'refuses the malformed host %j without a lookup',
      async (host) => {
        const table = standardTable();
        const app = await build(table.lookup);

        const response = await app.inject({ method: 'GET', url: '/api', headers: { host } });

        expect(response.statusCode).toBe(421);
        expect(response.json()).toMatchObject({ code: 'misdirected_request' });
        expect(table.lookup).not.toHaveBeenCalled();
        await app.close();
      }
    );

    it('answers 500 when the lookup fails, and caches nothing', async () => {
      const table = standardTable();
      table.lookup.mockRejectedValueOnce(new Error('connection refused'));
      const app = await build(table.lookup);

      const failed = await app.inject({
        method: 'GET',
        url: '/api',
        headers: { host: 'auth.example.com' },
      });
      const retried = await app.inject({
        method: 'GET',
        url: '/api',
        headers: { host: 'auth.example.com' },
      });

      expect(failed.statusCode).toBe(500);
      expect(failed.json()).toMatchObject({ code: 'internal_error' });
      expect(failed.headers['set-cookie']).toBeUndefined();
      expect(retried.statusCode).toBe(200);
      await app.close();
    });
  });

  describe('route surfaces', () => {
    it('serves browser routes on the primary host and refuses them on an endpoint host', async () => {
      const app = await build(standardTable().lookup);

      const onPrimary = await app.inject({
        method: 'GET',
        url: '/browser',
        headers: { host: 'auth.example.com' },
      });
      const onEndpoint = await app.inject({
        method: 'GET',
        url: '/browser',
        headers: { host: 'auth-server:3000' },
      });

      expect(onPrimary.statusCode).toBe(200);
      expect(onEndpoint.statusCode).toBe(421);
      expect(onEndpoint.headers['set-cookie']).toBeUndefined();
      await app.close();
    });

    it.each(['api', 'meta'])('serves %s routes on an endpoint host', async (surface) => {
      const app = await build(standardTable().lookup);

      const response = await app.inject({
        method: 'GET',
        url: `/${surface}`,
        headers: { host: 'auth-server:3000' },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        realm: 'a',
        realmHost: { host: 'auth-server', kind: 'endpoint' },
      });
      await app.close();
    });

    it('serves none routes on any host, without a lookup or a realm', async () => {
      const table = standardTable();
      const app = await build(table.lookup);

      for (const host of ['unknown.example', '*.bad', 'auth.example.com']) {
        const response = await app.inject({ method: 'GET', url: '/none', headers: { host } });

        expect(response.statusCode).toBe(200);
        expect(response.json()).toEqual({ realm: null, realmHost: null });
      }
      expect(table.lookup).not.toHaveBeenCalled();
      await app.close();
    });

    it('answers an unknown route with the same 404 on every host', async () => {
      const table = standardTable();
      const app = await build(table.lookup);

      const response = await app.inject({
        method: 'GET',
        url: '/nowhere',
        headers: { host: 'unknown.example' },
      });

      expect(response.statusCode).toBe(404);
      expect(table.lookup).not.toHaveBeenCalled();
      await app.close();
    });

    it('refuses to boot when a route has no surface class', async () => {
      const app = Fastify({ logger: false });
      await app.register(realmResolverPlugin, { lookup: standardTable().lookup });
      // Inside a plugin, as the autoloaded routes are.
      app.register(async (routes) => {
        routes.get('/ui/new-page', async () => 'unclassified');
      });

      await expect(app.ready()).rejects.toThrow(
        "Route GET /ui/new-page has no config.surface; set one of 'browser', 'api', 'meta', 'none'"
      );
    });

    it('refuses to boot when a route names a surface that is not a class', async () => {
      const app = Fastify({ logger: false });
      await app.register(realmResolverPlugin, { lookup: standardTable().lookup });
      app.register(async (routes) => {
        routes.get('/x', { config: { surface: 'public' as RouteSurface } }, async () => 'x');
      });

      await expect(app.ready()).rejects.toThrow(/^Route GET \/x has an unknown config\.surface/);
    });

    it("classes @fastify/cors's OPTIONS * preflight route as api", async () => {
      const app = Fastify({ logger: false });
      await app.register(realmResolverPlugin, { lookup: standardTable().lookup });
      await app.register(errorHandler);
      await app.register(cors, { origin: 'https://app.example.com' });
      await app.ready();

      const preflight = (host: string) =>
        app.inject({
          method: 'OPTIONS',
          url: '/oauth/token',
          headers: {
            host,
            origin: 'https://app.example.com',
            'access-control-request-method': 'POST',
          },
        });

      expect((await preflight('auth.example.com')).statusCode).toBe(204);
      expect((await preflight('auth-server')).statusCode).toBe(204);
      expect((await preflight('unknown.example')).statusCode).toBe(421);
      await app.close();
    });

    it('needs the database plugin when no lookup is given', async () => {
      const app = Fastify({ logger: false });
      app.register(realmResolverPlugin);

      await expect(app.ready()).rejects.toThrow(/register the database plugin first/);
    });
  });

  describe('the cache', () => {
    it('makes a new endpoint host visible within the cache time', async () => {
      let at = 1_000_000;
      const table = standardTable();
      const app = await build(table.lookup, { now: () => at });
      const onNewHost = () =>
        app.inject({ method: 'GET', url: '/api', headers: { host: 'portal-backend' } });

      expect((await onNewHost()).statusCode).toBe(421);
      table.add('portal-backend', 'endpoint', { name: 'a' });

      at += 4_999;
      expect((await onNewHost()).statusCode).toBe(421);
      at += 1;
      const visible = await onNewHost();
      expect(visible.statusCode).toBe(200);
      expect(visible.json()).toMatchObject({ realm: 'a' });
      await app.close();
    });

    it('reads realm_hosts again for every host after realmHostCache.clear()', async () => {
      const table = standardTable();
      const app = await build(table.lookup);
      const onNewHost = () =>
        app.inject({ method: 'GET', url: '/api', headers: { host: 'portal-backend' } });

      expect((await onNewHost()).statusCode).toBe(421);
      table.add('portal-backend', 'endpoint', { name: 'a' });
      app.realmHostCache.clear();

      expect((await onNewHost()).statusCode).toBe(200);
      await app.close();
    });

    it('refuses a realm disabled after it was cached once the cache time passes', async () => {
      let at = 1_000_000;
      const table = standardTable();
      const app = await build(table.lookup, { now: () => at, cacheTtlMs: 10_000 });
      const onB = () =>
        app.inject({ method: 'GET', url: '/api', headers: { host: 'b.example.com' } });

      expect((await onB()).statusCode).toBe(200);
      table.add('b.example.com', 'primary', { name: 'b', enabled: false });

      at += 9_999;
      expect((await onB()).statusCode).toBe(200);
      at += 1;
      expect((await onB()).statusCode).toBe(421);
      await app.close();
    });
  });

  describe('X-Forwarded-Host', () => {
    const forwarded = (app: FastifyInstance, remoteAddress = '127.0.0.1') =>
      app.inject({
        method: 'GET',
        url: '/api',
        remoteAddress,
        headers: { host: 'internal-lb.local', 'x-forwarded-host': 'b.example.com' },
      });

    it('is ignored when no proxy is trusted', async () => {
      const app = await build(standardTable().lookup);

      expect((await forwarded(app)).statusCode).toBe(421);
      await app.close();
    });

    it('is ignored from a peer that is not a TRUST_PROXY hop', async () => {
      const app = await build(standardTable().lookup, {}, { trustProxy: ['10.0.4.12'] });

      expect((await forwarded(app, '192.0.2.7')).statusCode).toBe(421);
      await app.close();
    });

    it('is used from a TRUST_PROXY hop', async () => {
      const app = await build(standardTable().lookup, {}, { trustProxy: ['10.0.4.12'] });

      const response = await forwarded(app, '10.0.4.12');

      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ realm: 'b' });
      await app.close();
    });
  });
});
