import { databasePlugin } from '@qauth-labs/fastify-plugin-db';
import { requireDockerOrSkip, truncateDomainTablesStatement } from '@qauth-labs/shared-testing';
import Fastify, { type FastifyInstance, type InjectOptions } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * REALM RESOLUTION BY HOST AGAINST A REAL POSTGRES (ADR-019 Decision 1,
 * issue #486).
 *
 * Each test empties the database, boots the real auth-server (whose boot step
 * creates the default realm `master` on `auth.example.com`, from `JWT_ISSUER`),
 * seeds whatever other realms it needs through the repositories, and sends
 * requests with the host it names. A probe route added beside the app's shows
 * what the resolver put on the request; `realm-routing.integration.test.ts`
 * shows the handlers using it (#487).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const REALM_HOST = 'auth.example.com';

/** The probe: an `api` route that answers with the resolved realm and host. */
const PROBE = '/__realm-probe__';

/** A sample of the app's routes on every surface but `none`. */
const REALM_ROUTES: readonly (InjectOptions & { readonly url: string })[] = [
  { method: 'GET', url: '/' },
  { method: 'GET', url: '/.well-known/openid-configuration' },
  { method: 'GET', url: '/.well-known/oauth-authorization-server' },
  { method: 'GET', url: '/.well-known/jwks.json' },
  { method: 'GET', url: '/oauth/authorize?response_type=code&client_id=c' },
  { method: 'POST', url: '/oauth/token', payload: { grant_type: 'client_credentials' } },
  { method: 'GET', url: '/oauth/userinfo' },
  { method: 'GET', url: '/ui/login' },
  { method: 'GET', url: '/ui/consent' },
  { method: 'GET', url: '/consents' },
  { method: 'GET', url: '/api/clients' },
  { method: 'POST', url: '/auth/login', payload: { email: 'a@example.com', password: 'x' } },
  { method: 'GET', url: '/metrics' },
];

/** The OAuth protocol endpoints above, which answer the RFC 6749 error body (#513). */
const OAUTH_ENDPOINTS: ReadonlySet<string> = new Set([
  '/oauth/authorize',
  '/oauth/token',
  '/oauth/userinfo',
]);

/** The routes that read or set the session cookie, refused on an endpoint host. */
const BROWSER_ROUTES: readonly InjectOptions[] = [
  { method: 'GET', url: '/oauth/authorize?response_type=code&client_id=c' },
  { method: 'POST', url: '/oauth/authorize', payload: { response_type: 'code' } },
  { method: 'GET', url: '/ui/login' },
  { method: 'POST', url: '/ui/login', payload: { email: 'a@example.com' } },
  { method: 'GET', url: '/ui/consent' },
  { method: 'GET', url: '/ui/resume/abc' },
  { method: 'GET', url: '/consents' },
  { method: 'DELETE', url: '/consents/0190e3c4-0000-7000-8000-000000000001' },
];

interface ProbeAnswer {
  readonly realm: { readonly name: string; readonly issuer: string | null } | null;
  readonly realmHost: { readonly host: string; readonly kind: string } | null;
}

describe('realm resolution by host on a real Postgres (#486)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let admin: FastifyInstance | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
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
    await Promise.all(booted.splice(0).map(async (server) => server.close()));
  });

  function database(): FastifyInstance {
    if (!admin) throw new Error('database not started');
    return admin;
  }

  function realms(): FastifyInstance['repositories']['realms'] {
    return database().repositories.realms;
  }

  /** Boot the real auth-server with the probe route, on top of the base environment. */
  async function boot(environment: Record<string, string> = {}): Promise<FastifyInstance> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    const server = await bootAuthServer(
      { ...baseEnvironment(infra, jwt), ...environment },
      {
        routes: (app) => {
          app.get(PROBE, { config: { surface: 'api' } }, async (request) => ({
            realm:
              request.realm === null
                ? null
                : { name: request.realm.name, issuer: request.realm.issuer },
            realmHost: request.realmHost,
          }));
        },
      }
    );
    booted.push(server);
    return server.app;
  }

  async function probe(
    app: FastifyInstance,
    headers: Record<string, string>,
    remoteAddress?: string
  ) {
    return app.inject({
      method: 'GET',
      url: PROBE,
      headers,
      ...(remoteAddress === undefined ? {} : { remoteAddress }),
    });
  }

  async function seedRealm(name: string, options: { enabled?: boolean } = {}): Promise<string> {
    const { realm } = await realms().createWithPrimaryHost(
      { name, issuer: `https://${name}.example.com`, enabled: options.enabled ?? true },
      `${name}.example.com`
    );
    return realm.id;
  }

  /**
   * Assert a response is the bare 421: no cookie, no realm in the body.
   *
   * The body is the error format of the route `url` names (#513): an OAuth
   * protocol endpoint answers the RFC 6749 body, every other route a problem
   * document. A problem document's `instance` echoes the path the caller sent,
   * which is not realm data, so it is left out of the leak check.
   */
  function expectMisdirected(
    response: Awaited<ReturnType<FastifyInstance['inject']>>,
    url: string = PROBE
  ): void {
    expect(response.statusCode).toBe(421);
    expect(response.headers['set-cookie']).toBeUndefined();
    const path = url.split('?')[0];
    const body = response.json() as Record<string, unknown>;
    if (OAUTH_ENDPOINTS.has(path)) {
      expect(response.headers['content-type']).toMatch(/^application\/json(?:;|$)/);
      expect(body).toEqual({ error: 'invalid_request', error_description: expect.any(String) });
    } else {
      expect(response.headers['content-type']).toMatch(/^application\/problem\+json(?:;|$)/);
      expect(body).toEqual({
        type: expect.any(String),
        title: expect.any(String),
        status: 421,
        detail: expect.any(String),
        instance: path,
        code: 'misdirected_request',
        trace_id: expect.any(String),
      });
    }
    const disclosed = JSON.stringify({ ...body, instance: undefined });
    for (const realmData of ['master', 'example.com', 'issuer', 'jwks']) {
      expect(disclosed).not.toContain(realmData);
    }
  }

  describe('the realm a host names', () => {
    it('gives realm A on its host and realm B on its own, and decorates the full row', async () => {
      const app = await boot();
      await seedRealm('beta');

      const onA = await probe(app, { host: REALM_HOST });
      const onB = await probe(app, { host: 'BETA.example.com:443' });

      expect(onA.statusCode).toBe(200);
      expect(onA.json<ProbeAnswer>()).toEqual({
        realm: { name: 'master', issuer: 'https://auth.example.com' },
        realmHost: { host: REALM_HOST, kind: 'primary' },
      });
      expect(onB.json<ProbeAnswer>()).toEqual({
        realm: { name: 'beta', issuer: 'https://beta.example.com' },
        realmHost: { host: 'beta.example.com', kind: 'primary' },
      });
    });

    it('sends a request with no host to the realm host, as the harness promises', async () => {
      const app = await boot();

      const response = await app.inject({ method: 'GET', url: PROBE });

      expect(response.json<ProbeAnswer>().realmHost).toEqual({ host: REALM_HOST, kind: 'primary' });
    });

    it('answers an unknown host with 421 on every realm route: no cookie, no discovery, no fallback', async () => {
      const app = await boot();

      // The login page sets a cookie on the realm host, so its absence below
      // is the resolver's doing.
      const onRealmHost = await app.inject({ method: 'GET', url: '/ui/login' });
      expect(onRealmHost.statusCode).toBe(200);
      expect(onRealmHost.headers['set-cookie']).toBeDefined();

      for (const host of ['unknown.example', 'localhost', '127.0.0.1:3000', 'example.com']) {
        expectMisdirected(await probe(app, { host }));
        for (const route of REALM_ROUTES) {
          expectMisdirected(await app.inject({ ...route, headers: { host } }), route.url);
        }
      }
    });

    it('answers a disabled realm with 421', async () => {
      const app = await boot();
      await seedRealm('gamma', { enabled: false });

      expectMisdirected(await probe(app, { host: 'gamma.example.com' }));
      expectMisdirected(
        await app.inject({
          method: 'GET',
          url: '/.well-known/openid-configuration',
          headers: { host: 'gamma.example.com' },
        }),
        '/.well-known/openid-configuration'
      );
    });

    it('answers a realm with no issuer with 421', async () => {
      const app = await boot();
      const legacy = await realms().create({ name: 'legacy', enabled: true });
      await realms().addEndpointHost(legacy.id, 'legacy-internal');

      expectMisdirected(await probe(app, { host: 'legacy-internal' }));
    });
  });

  describe('/health', () => {
    it('answers 200 on an unknown host, with no realm data', async () => {
      const app = await boot();

      for (const host of ['unknown.example', '10.1.2.3:8080', '*.example.com']) {
        const response = await app.inject({ method: 'GET', url: '/health', headers: { host } });

        expect(response.statusCode).toBe(200);
        expect(response.json()).toMatchObject({ status: 'ok' });
        expect(response.body).not.toContain('master');
        expect(response.body).not.toContain(REALM_HOST);
      }
    });
  });

  describe('endpoint hosts', () => {
    it('resolves the realm for an API route on an endpoint host, and refuses a browser route there', async () => {
      const app = await boot({ DEFAULT_REALM_ENDPOINT_HOSTS: 'auth-server' });

      const onEndpoint = await probe(app, { host: 'auth-server:3000' });
      expect(onEndpoint.statusCode).toBe(200);
      expect(onEndpoint.json<ProbeAnswer>()).toEqual({
        realm: { name: 'master', issuer: 'https://auth.example.com' },
        realmHost: { host: 'auth-server', kind: 'endpoint' },
      });

      for (const route of [
        { method: 'GET', url: '/.well-known/openid-configuration' },
        { method: 'GET', url: '/.well-known/jwks.json' },
      ] as const) {
        const response = await app.inject({ ...route, headers: { host: 'auth-server:3000' } });
        expect(response.statusCode, route.url).toBe(200);
      }
      const token = await app.inject({
        method: 'POST',
        url: '/oauth/token',
        headers: { host: 'auth-server:3000' },
        payload: { grant_type: 'client_credentials', client_id: 'nobody', client_secret: 'x' },
      });
      expect(token.statusCode).not.toBe(421);
      expect(token.json()).toMatchObject({ error: 'invalid_client' });

      for (const route of BROWSER_ROUTES) {
        const response = await app.inject({ ...route, headers: { host: 'auth-server:3000' } });
        expect(response.statusCode, `${route.method} ${route.url}`).toBe(421);
        expect(response.headers['set-cookie']).toBeUndefined();
      }
    });

    it('answers an endpoint host added at runtime within the cache time', async () => {
      const app = await boot();
      const master = await realms().findByName('master');

      expectMisdirected(await probe(app, { host: 'portal-backend' }));
      await realms().addEndpointHost(master?.id ?? '', 'portal-backend');

      // A miss is cached for at most 5 s; wait it out rather than fake a clock.
      await new Promise((resolve) => setTimeout(resolve, 5_100));
      const response = await probe(app, { host: 'portal-backend' });
      expect(response.statusCode).toBe(200);
      expect(response.json<ProbeAnswer>().realmHost).toEqual({
        host: 'portal-backend',
        kind: 'endpoint',
      });
    }, 20_000);
  });

  describe('simple mode', () => {
    it('answers only the configured host and its endpoint hosts, with one realm', async () => {
      const app = await boot({ DEFAULT_REALM_ENDPOINT_HOSTS: 'auth-server,10.0.0.5' });
      const { rows } = await database().dbPool.query<{ count: string }>(
        'SELECT count(*) FROM realms'
      );
      expect(Number(rows[0].count)).toBe(1);

      for (const host of [REALM_HOST, 'auth-server', 'auth-server:3000', '10.0.0.5:3000']) {
        const response = await app.inject({
          method: 'GET',
          url: '/.well-known/openid-configuration',
          headers: { host },
        });
        expect(response.statusCode, host).toBe(200);
        expect(response.json()).toMatchObject({ issuer: 'https://auth.example.com' });
      }
      for (const host of ['other.example.com', 'login.example.com', 'localhost', '10.0.0.6']) {
        expectMisdirected(
          await app.inject({
            method: 'GET',
            url: '/.well-known/openid-configuration',
            headers: { host },
          }),
          '/.well-known/openid-configuration'
        );
      }
    });
  });

  describe('X-Forwarded-Host', () => {
    it('is ignored from a peer that TRUST_PROXY does not list', async () => {
      const app = await boot();
      await seedRealm('beta');

      // An unknown host stays unknown whatever the forwarded host says.
      expectMisdirected(
        await probe(app, { host: 'internal-lb.local', 'x-forwarded-host': REALM_HOST })
      );
      // And a realm host keeps its realm.
      const kept = await probe(app, { host: REALM_HOST, 'x-forwarded-host': 'beta.example.com' });
      expect(kept.json<ProbeAnswer>().realm?.name).toBe('master');
    });

    it('is ignored from a peer outside the TRUST_PROXY list when one is set', async () => {
      const app = await boot({ TRUST_PROXY: '10.0.4.12' });
      await seedRealm('beta');

      const response = await probe(
        app,
        { host: REALM_HOST, 'x-forwarded-host': 'beta.example.com' },
        '192.0.2.7'
      );
      expect(response.json<ProbeAnswer>().realm?.name).toBe('master');
    });

    it('is used from a TRUST_PROXY hop', async () => {
      const app = await boot({ TRUST_PROXY: '10.0.4.12' });
      await seedRealm('beta');

      const response = await probe(
        app,
        { host: 'internal-lb.local', 'x-forwarded-host': 'beta.example.com' },
        '10.0.4.12'
      );
      expect(response.statusCode).toBe(200);
      expect(response.json<ProbeAnswer>()).toMatchObject({
        realm: { name: 'beta' },
        realmHost: { host: 'beta.example.com', kind: 'primary' },
      });
    });
  });
});
