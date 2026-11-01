/**
 * NO ROUTE ANSWERS ON BOTH LISTENERS (#496).
 *
 * Boots the real app as a split process holding the signer, with the
 * internal listener beside it as `main.ts` builds it: real TLS files, real
 * mutual TLS on loopback, and a fixture route module in place of the
 * manifest's (empty until #497). No database or Redis: no request reaches a
 * route that reads one. Then every route of the public listener is sent to
 * the internal listener, and every route of the internal listener to the
 * public one, and each answers 404.
 */
import { generateKeyPairSync } from 'node:crypto';
import type { AddressInfo } from 'node:net';

import Fastify, { type FastifyInstance, type RouteOptions } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';

import { createInternalPki, type TlsFileDirectory, writeTlsFiles } from '../testing/internal-pki';
import { createInternalClient, type InternalClient } from './internal/client';
import type { InternalRouteModule } from './internal/route-manifest';

/** The keys a boot sets or clears, restored after the file. */
const BOOT_KEYS = /^(OID4VP_|WALLET_|SSF_|JWT_|KEK|SERVICE_ROLES$|SIGNER_URL$|INTERNAL_)/;

const FIXTURE_MODULE: InternalRouteModule = {
  module: 'fixture',
  prefix: '/internal/fixture/v1-rc.0',
  roles: ['signer'],
  peerRoles: ['web'],
  load: async () => ({
    default: async (scope) => {
      scope.get('/peer', async (request) => ({ peerRole: request.peerRole }));
      scope.post('/sign', async () => ({ signed: true }));
      scope.get('/keys/:kid', async () => ({ kid: true }));
    },
  }),
};

const savedEnv = new Map<string, string | undefined>();
let tlsDirectory: TlsFileDirectory;
let publicServer: FastifyInstance;
let internal: FastifyInstance;
let client: InternalClient;
const publicRoutes: RouteOptions[] = [];
const internalRoutes: RouteOptions[] = [];

/** A concrete path for a route's pattern. */
function concretePath(url: string): string {
  if (url === '*') return '/';
  return url.replace(/:[A-Za-z0-9_]+/g, 'x').replace(/\*/g, 'x');
}

/** Each method of each route, with a concrete path. */
function requests(routes: readonly RouteOptions[]): Array<{ method: string; path: string }> {
  return routes.flatMap((route) =>
    [route.method]
      .flat()
      .map((method) => ({ method: String(method), path: concretePath(route.url) }))
  );
}

beforeAll(async () => {
  const pki = createInternalPki();
  const signer = pki.issue({ dnsNames: ['signer.qauth.internal'] });
  const web = pki.issue({ uris: ['spiffe://qauth.test/web'] });
  tlsDirectory = writeTlsFiles(signer, pki.caPem);
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');

  const environment: Record<string, string> = {
    NODE_ENV: 'test',
    SERVICE_ROLES: 'api,signer',
    JWT_ISSUER: 'https://auth.example.com',
    JWT_PUBLIC_KEY: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    JWT_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    INTERNAL_TLS_CERT_PATH: tlsDirectory.files.certPath,
    INTERNAL_TLS_KEY_PATH: tlsDirectory.files.keyPath,
    INTERNAL_TLS_CA_PATH: tlsDirectory.files.caPath,
    INTERNAL_PEER_ROLES: JSON.stringify({ 'spiffe://qauth.test/web': 'web' }),
    SESSION_COOKIE_SECRET: 'internal-listener-session-secret-of-32-characters',
    EMAIL_PROVIDER: 'mock',
    EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
    EMAIL_BASE_URL: 'https://auth.example.com',
    DEFAULT_REALM_NAME: 'master',
    ENABLE_SWAGGER: 'false',
    LOG_LEVEL: 'fatal',
    // Never dialled: no request reaches a route that reads either.
    DATABASE_URL: 'postgres://qauth:qauth@127.0.0.1:1/qauth-unreachable',
    REDIS_URL: 'redis://127.0.0.1:1',
    RATE_LIMIT_ENABLED: 'false',
    METRICS_ENABLED: 'true',
    SSF_TRANSMITTER_ENABLED: 'true',
  };
  for (const key of Object.keys(process.env)) {
    if (BOOT_KEYS.test(key)) {
      savedEnv.set(key, process.env[key]);
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries(environment)) {
    if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
    process.env[key] = value;
  }
  // `config/env.ts` parses the environment at load.
  vi.resetModules();
  const { app } = await import('./app');
  const { env } = await import('../config/env');
  const { internalListenerPlan } = await import('./service-roles');
  const { createInternalServer } = await import('./internal/listener');
  const { readInternalTlsFiles } = await import('./internal/tls-files');
  const { answerRouteNotFound, answerUnknownRouteBeforeBody } =
    await import('./helpers/request-bounds');

  // As `main.ts` builds it.
  const plan = internalListenerPlan(env);
  if (!plan.serves || plan.tls === undefined || plan.problems.length > 0) {
    throw new Error(`the plan does not serve mutual TLS: ${JSON.stringify(plan)}`);
  }
  internal = createInternalServer({
    peerRoles: plan.peerRoles,
    tls: { files: plan.tls, material: readInternalTlsFiles(plan.tls) },
  });
  internal.addHook('onRoute', (route) => {
    internalRoutes.push(route);
  });

  publicServer = Fastify({ logger: false, routerOptions: { ignoreTrailingSlash: true } });
  publicServer.setValidatorCompiler(validatorCompiler);
  publicServer.setSerializerCompiler(serializerCompiler);
  publicServer.addHook('onRequest', answerUnknownRouteBeforeBody);
  publicServer.setNotFoundHandler(answerRouteNotFound);
  await publicServer.register(async (scope) => {
    scope.addHook('onRoute', (route) => {
      publicRoutes.push(route);
    });
    await app(scope, {
      defaultRealmBoot: false,
      realmLookup: async () => undefined,
      internalListener: { server: internal, modules: [FIXTURE_MODULE] },
    });
  });
  await publicServer.ready();
  await internal.listen({ host: '127.0.0.1', port: 0 });
  client = createInternalClient({
    url: `https://127.0.0.1:${(internal.server.address() as AddressInfo).port}`,
    cert: web.cert,
    key: web.key,
    ca: pki.caPem,
    expectedServerSan: 'signer.qauth.internal',
  });
}, 120_000);

afterAll(async () => {
  client?.close();
  await publicServer?.close();
  tlsDirectory?.remove();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe('the two listeners of one process', () => {
  it('serves the internal routes on the internal listener, for a known peer', async () => {
    expect(requests(internalRoutes)).toEqual([
      { method: 'GET', path: '/internal/fixture/v1-rc.0/peer' },
      { method: 'POST', path: '/internal/fixture/v1-rc.0/sign' },
      { method: 'GET', path: '/internal/fixture/v1-rc.0/keys/x' },
    ]);
    const response = await client.request({
      method: 'GET',
      path: '/internal/fixture/v1-rc.0/peer',
    });
    expect(JSON.parse(response.body.toString())).toEqual({ peerRole: 'web' });
  });

  it('answers no route of the internal listener on the public one', async () => {
    for (const { method, path } of requests(internalRoutes)) {
      expect(publicServer.hasRoute({ method: method as never, url: path })).toBe(false);
      const response = await publicServer.inject({ method: method as never, url: path });
      expect(response.statusCode, `${method} ${path}`).toBe(404);
      expect(response.json()).toMatchObject({ code: 'not_found' });
    }
  });

  it('answers no route of the public listener on the internal one', async () => {
    const sent = requests(publicRoutes);
    expect(sent.length).toBeGreaterThan(30);
    expect(sent).toContainEqual({ method: 'POST', path: '/oauth/token' });
    for (const { method, path } of sent) {
      const response = await client.request({ method: method as never, path });
      expect(response.status, `${method} ${path}`).toBe(404);
    }
  });

  it('gives the internal routes the roles of their module', () => {
    for (const route of internalRoutes) {
      expect(route.config?.serviceRoles, route.url).toEqual(['signer']);
    }
  });
});
