/**
 * LIVENESS, READINESS AND THE METRICS' NEW HOME, against a real Postgres and
 * Redis (ADR-019 Decisions 1 and 8, issue #500).
 *
 * - `GET /health` answers 200 while Postgres is unreachable, and `GET /ready`
 *   answers 503 naming `database`.
 * - An `api` process with Redis unreachable answers `/ready` with 503 naming
 *   `redis`.
 * - A `signer` process whose KEK is not the one its keys were sealed under
 *   answers `/ready` with 503 naming `kek`.
 * - Both answer on an unknown `Host`, with no realm data.
 * - The metrics are absent on the public listener and served on the internal
 *   one, to a peer mapped to `metrics` alone.
 * - A check registered beside the role checks appears in `/ready`.
 *
 * Postgres and Redis are shared by the run, so a dependency is taken away
 * from one server by a TCP relay between them (`testing/tcp-relay.ts`).
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */
import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootAuthServerOptions,
  type BootedAuthServer,
  E2E_REALM_NAME,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  startE2eInfrastructure,
} from '../testing/e2e-harness';
import { createInternalPki, type TlsFileDirectory, writeTlsFiles } from '../testing/internal-pki';
import { SIGNER_LISTENER, SIGNER_SERVICE } from '../testing/service-role-env';
import { startTcpRelay, type TcpRelay } from '../testing/tcp-relay';
import { createInternalClient, type InternalClient } from './internal/client';

/**
 * What `/ready` answers: `status` is `ok` with a 200, and with a 503 the
 * problem document's 503, whose `code` is `service_unavailable`.
 */
interface ReadyAnswer {
  readonly status: 'ok' | 503;
  readonly code?: string;
  readonly roles: readonly string[];
  readonly checks: Record<string, { readonly status: 'ok' | 'fail'; readonly reason?: string }>;
}

/** The SAN of the process's internal listener certificate, and of its two peers. */
const SERVER_SAN = 'spiffe://qauth.test/auth-server';
const SCRAPER_SAN = 'spiffe://qauth.test/prometheus';
const WEB_SAN = 'spiffe://qauth.test/web';

describe('health and readiness (#500)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  const booted: BootedAuthServer[] = [];
  const relays: TcpRelay[] = [];
  const clients: InternalClient[] = [];
  const tlsDirectories: TlsFileDirectory[] = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  afterEach(async () => {
    for (const client of clients.splice(0)) client.close();
    for (const server of booted.splice(0)) {
      // A server whose Redis went away would wait for it on close.
      server.app.redis.disconnect();
      await server.close().catch(() => undefined);
    }
    await Promise.all(relays.splice(0).map((relay) => relay.stop()));
    for (const directory of tlsDirectories.splice(0)) directory.remove();
  });

  function environment(): Record<string, string> {
    if (!infra || !jwt) throw new Error('infrastructure not started');
    return baseEnvironment(infra, jwt);
  }

  /** The environment of a split process without the signer: no KEK, no private key. */
  function withoutSigner(serviceRoles: string): Record<string, string> {
    const { KEK: _kek, JWT_PRIVATE_KEY: _privateKey, ...rest } = environment();
    return { ...rest, ...SIGNER_SERVICE, SERVICE_ROLES: serviceRoles };
  }

  async function boot(
    env: Record<string, string>,
    options: BootAuthServerOptions = {}
  ): Promise<BootedAuthServer> {
    const server = await bootAuthServer(env, options);
    booted.push(server);
    return server;
  }

  async function relayTo(url: string): Promise<TcpRelay> {
    const parsed = new URL(url);
    const relay = await startTcpRelay({ host: parsed.hostname, port: Number(parsed.port) });
    relays.push(relay);
    return relay;
  }

  async function ready(app: FastifyInstance, host?: string) {
    const response = await app.inject({
      method: 'GET',
      url: '/ready',
      ...(host === undefined ? {} : { headers: { host } }),
    });
    return { statusCode: response.statusCode, body: response.json<ReadyAnswer>(), raw: response };
  }

  it('answers /health with 200 and /ready with 503 naming database while Postgres is unreachable', async () => {
    const env = environment();
    const relay = await relayTo(env['DATABASE_URL'] as string);
    const { app } = await boot({
      ...env,
      DATABASE_URL: relay.through(env['DATABASE_URL'] as string),
    });

    const before = await ready(app);
    expect(before.statusCode).toBe(200);
    expect(before.body).toMatchObject({
      status: 'ok',
      checks: {
        database: { status: 'ok' },
        redis: { status: 'ok' },
        kek: { status: 'ok' },
        outbox: { status: 'ok' },
      },
    });

    await relay.stop();

    const health = await app.inject({ method: 'GET', url: '/health' });
    expect(health.statusCode).toBe(200);
    expect(health.json()).toMatchObject({ status: 'ok' });

    const after = await ready(app);
    expect(after.statusCode).toBe(503);
    expect(after.body.code).toBe('service_unavailable');
    expect(after.body.checks['database']).toEqual({ status: 'fail', reason: expect.any(String) });
    expect(after.body.checks['redis']).toEqual({ status: 'ok' });
    // The answer names the check, never the error.
    expect(after.raw.body).not.toMatch(/ECONNREFUSED|127\.0\.0\.1|password/i);
  }, 120_000);

  it('answers /ready with 503 naming redis on an api process whose Redis is unreachable', async () => {
    const env = withoutSigner('api');
    const relay = await relayTo(env['REDIS_URL'] as string);
    const { app } = await boot({ ...env, REDIS_URL: relay.through(env['REDIS_URL'] as string) });

    const before = await ready(app);
    expect(before.statusCode).toBe(200);
    expect(before.body).toEqual({
      status: 'ok',
      roles: ['api'],
      checks: { database: { status: 'ok' }, redis: { status: 'ok' } },
    });

    await relay.stop();

    const after = await ready(app);
    expect(after.statusCode).toBe(503);
    expect(after.body).toMatchObject({
      status: 503,
      code: 'service_unavailable',
      detail: 'A readiness check failed: redis.',
      roles: ['api'],
      checks: {
        database: { status: 'ok' },
        redis: { status: 'fail', reason: expect.stringMatching(/^(error|timeout)$/) },
      },
    });
    // Liveness does not wait for Redis: its rate limit counts in memory.
    const health = await app.inject({ method: 'GET', url: '/health' });
    expect(health.statusCode).toBe(200);
  }, 120_000);

  it('answers /ready with 503 naming kek on a signer process whose KEK did not seal its keys', async () => {
    // A single process creates the default realm's keys, sealed under the KEK.
    const all = await boot(environment());
    await all.close();
    booted.splice(booted.indexOf(all), 1);

    // With the same KEK, the signer opens a stored key.
    const signerEnv = { ...environment(), ...SIGNER_LISTENER, SERVICE_ROLES: 'signer' };
    const right = await boot(signerEnv, { defaultRealmBoot: false });
    const passing = await ready(right.app);
    expect(passing.statusCode).toBe(200);
    expect(passing.body).toEqual({
      status: 'ok',
      roles: ['signer'],
      checks: { database: { status: 'ok' }, kek: { status: 'ok' } },
    });
    await right.close();
    booted.splice(booted.indexOf(right), 1);

    // Another KEK cannot: the process is alive, and not ready.
    const wrong = await boot(
      { ...signerEnv, KEK: Buffer.alloc(32, 0x5a).toString('base64') },
      { defaultRealmBoot: false }
    );
    expect((await wrong.app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
    const failing = await ready(wrong.app);
    expect(failing.statusCode).toBe(503);
    expect(failing.body).toMatchObject({
      status: 503,
      code: 'service_unavailable',
      roles: ['signer'],
      checks: { database: { status: 'ok' }, kek: { status: 'fail', reason: 'error' } },
    });
  }, 180_000);

  it('answers both on an unknown Host, with no realm data', async () => {
    const { app } = await boot(environment());

    for (const url of ['/health', '/ready']) {
      for (const host of ['unknown.example', '203.0.113.9:8443']) {
        const response = await app.inject({ method: 'GET', url, headers: { host } });
        expect(response.statusCode, `${url} on ${host}`).toBe(200);
        expect(response.body).not.toContain(E2E_REALM_NAME);
        expect(response.body).not.toContain('auth.example.com');
        expect(Object.keys(response.json<object>()).sort(), url).toEqual(
          url === '/health' ? ['roles', 'status', 'timestamp'] : ['checks', 'roles', 'status']
        );
        expect(response.headers['cache-control']).toBe('no-store');
      }
    }
  }, 120_000);

  it('serves the metrics on the internal listener to the metrics peer alone, and not on the public one', async () => {
    const pki = createInternalPki();
    const tls = writeTlsFiles(pki.issue({ uris: [SERVER_SAN] }), pki.caPem);
    tlsDirectories.push(tls);
    const server = await boot(
      {
        ...withoutSigner('api'),
        INTERNAL_TLS_CERT_PATH: tls.files.certPath,
        INTERNAL_TLS_KEY_PATH: tls.files.keyPath,
        INTERNAL_TLS_CA_PATH: tls.files.caPath,
        INTERNAL_PEER_ROLES: JSON.stringify({ [SCRAPER_SAN]: 'metrics', [WEB_SAN]: 'web' }),
      },
      { internalListener: () => ({}) }
    );

    // The public listener has no metrics, on any host.
    for (const host of [undefined, 'unknown.example']) {
      const onPublic = await server.app.inject({
        method: 'GET',
        url: '/metrics',
        ...(host === undefined ? {} : { headers: { host } }),
      });
      expect(onPublic.statusCode, String(host)).toBe(404);
      expect(onPublic.body).not.toContain('qauth_');
    }

    const clientFor = (san: string) => {
      const client = createInternalClient({
        url: server.internalUrl as string,
        ...pki.issue({ uris: [san] }),
        ca: pki.caPem,
        expectedServerSan: SERVER_SAN,
      });
      clients.push(client);
      return client;
    };

    const scraped = await clientFor(SCRAPER_SAN).request({
      method: 'GET',
      path: '/internal/metrics',
    });
    expect(scraped.status).toBe(200);
    expect(scraped.body.toString()).toMatch(/^qauth_/m);

    const refused = await clientFor(WEB_SAN).request({ method: 'GET', path: '/internal/metrics' });
    expect(refused.status).toBe(403);
    expect(refused.body.toString()).not.toContain('qauth_');
  }, 120_000);

  it('lists a check registered beside the role checks, and answers 503 while it fails', async () => {
    let healthy = true;
    const { app } = await boot(withoutSigner('web'), {
      routes: (scope) => {
        scope.readiness.register({
          name: 'extra_dependency',
          run: async () => {
            if (!healthy) throw new Error('the extra dependency is down');
          },
        });
      },
    });

    const passing = await ready(app);
    expect(passing.statusCode).toBe(200);
    expect(passing.body.checks).toEqual({
      database: { status: 'ok' },
      redis: { status: 'ok' },
      extra_dependency: { status: 'ok' },
    });

    healthy = false;
    const failing = await ready(app);
    expect(failing.statusCode).toBe(503);
    expect(failing.body.checks).toEqual({
      database: { status: 'ok' },
      redis: { status: 'ok' },
      extra_dependency: { status: 'fail', reason: 'error' },
    });
  }, 120_000);
});
