/**
 * EVERY ROUTE OF THE ASSEMBLED APP HAS A SURFACE CLASS (#486) AND THE ERROR
 * FORMAT OF ITS KIND (#513).
 *
 * The realm resolver (`plugins/realm-resolver.ts`) refuses to boot when a route
 * has no `config.surface`, so the boot in `beforeAll` is the first half of
 * this test: an unclassified route fails it. The second half checks the
 * classes themselves against the rule ADR-019 Decisions 1 and 8 give: the
 * routes that read or set the browser session cookie are `browser`, `/health`
 * is the one `none` route, and everything else is `api` or `meta`.
 *
 * The app boots with every switch that registers a route turned on, the
 * maximal surface of `openapi-export.ts`, so the wallet routes and the passkey
 * association files are checked too. No database or Redis: the routes are read
 * as they register. The CORS checks (#930) send requests, which the app
 * answers before anything reaches either: a preflight from an `onRequest`
 * hook, and a call to the authorization or token endpoint from its schema
 * validation.
 */
import { generateKeyPairSync } from 'node:crypto';

import Fastify, {
  type FastifyInstance,
  type LightMyRequestResponse,
  type RouteOptions,
} from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import type { RealmHostLookup, RealmHostMatch } from './helpers/realm-host-cache';
import { routeSurfaceProblem } from './helpers/route-surface';

/** The origin `CORS_ORIGIN` lists: a browser-based application's (#930). */
const SPA_ORIGIN = 'https://spa.example.com';

/**
 * The realm the resolver (#486) finds for `localhost`, the host `inject()`
 * sends. The database is unreachable, so hosts are looked up here instead.
 */
const realmLookup: RealmHostLookup = async (host) =>
  host === 'localhost'
    ? ({
        realm: {
          id: '0190e3c4-0000-7000-8000-000000000001',
          name: 'master',
          enabled: true,
          issuer: 'https://auth.example.com',
        },
        host: { host: 'localhost', kind: 'primary' },
      } as RealmHostMatch)
    : undefined;

/** The environment of a deployment with every route-registering switch on. */
function maximalEnvironment(): Record<string, string> {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    NODE_ENV: 'test',
    JWT_ISSUER: 'https://auth.example.com',
    JWT_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    JWT_PUBLIC_KEY: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    SESSION_COOKIE_SECRET: 'route-surfaces-session-secret-of-at-least-32-characters',
    EMAIL_PROVIDER: 'mock',
    EMAIL_FROM_ADDRESS: 'no-reply@auth.example.com',
    EMAIL_BASE_URL: 'https://auth.example.com',
    DEFAULT_REALM_NAME: 'master',
    ENABLE_SWAGGER: 'false',
    LOG_LEVEL: 'fatal',
    // Never dialled: no request is sent.
    DATABASE_URL: 'postgres://qauth:qauth@127.0.0.1:1/qauth-unreachable',
    REDIS_URL: 'redis://127.0.0.1:1',
    RATE_LIMIT_ENABLED: 'false',
    METRICS_ENABLED: 'true',
    // A browser-based application's origin, as an operator lists it (#930).
    CORS_ORIGIN: SPA_ORIGIN,
    // The SSF transmitter's routes (#410): problem routes, though they speak an
    // OpenID protocol, because SSF 1.0 §8.1 defines no error body (#513).
    SSF_TRANSMITTER_ENABLED: 'true',
    // The switches `openapi-export.ts --surface maximal` sets, for the same routes.
    WALLET_FEDERATION_ENABLED: 'true',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup',
    OID4VP_SUBJECT_BINDING_CLAIMS: 'family_name,given_name,birth_date',
    WEBAUTHN_RP_ID: '',
    WEBAUTHN_APPLE_APP_IDS: 'ABCDE12345.com.example.app',
    WEBAUTHN_ANDROID_APPS: JSON.stringify({
      'com.example.app': [
        'FA:C6:17:45:DC:09:03:78:6F:B9:ED:E6:2A:96:2B:39:9F:73:48:F0:BB:6F:89:9B:83:32:66:75:91:03:3B:9C',
      ],
    }),
  };
}

/**
 * The routes that read or set a browser cookie: the session cookie, or the
 * login-CSRF cookie of a form that posts to a `/ui/*` route. The page the
 * verification mail links to, `GET /auth/verify`, is one; `POST /auth/verify`
 * beside it is the JSON API.
 */
function isBrowserSessionRoute(route: RouteOptions): boolean {
  const { url } = route;
  if (url === '/auth/verify') {
    return [route.method].flat().every((method) => method === 'GET' || method === 'HEAD');
  }
  return (
    url.startsWith('/ui/') ||
    url === '/oauth/authorize' ||
    url === '/consents' ||
    url.startsWith('/consents/') ||
    url === '/auth/link/wallet' ||
    url.startsWith('/auth/link/wallet/')
  );
}

/**
 * The OAuth protocol endpoints (ADR-019 Decision 7, #513): the routes whose
 * error response an OAuth, OpenID Connect or OpenID for Verifiable
 * Presentations specification defines. They, and only they, answer the
 * `oauth` error format; every other route answers problem documents. The
 * device authorization and FiPA authorization challenge endpoints join this
 * list when they are built.
 */
const OAUTH_PROTOCOL_ENDPOINTS = new Set([
  'GET /oauth/authorize',
  'POST /oauth/authorize',
  'POST /oauth/token',
  'POST /oauth/introspect',
  'POST /oauth/revoke',
  'POST /oauth/register',
  'GET /oauth/userinfo',
  'POST /oauth/userinfo',
  'GET /oid4vp/request/:handle',
  'POST /oid4vp/response',
]);

let server: FastifyInstance | undefined;
/** Every route as it registered; read after the boot, once every `onRoute` hook ran. */
const routes: RouteOptions[] = [];
const savedEnv = new Map<string, string | undefined>();

beforeAll(async () => {
  for (const key of Object.keys(process.env)) {
    if (/^(OID4VP_|WALLET_|ACR_|WEBAUTHN_|CORS_)/.test(key)) {
      savedEnv.set(key, process.env[key]);
      delete process.env[key];
    }
  }
  for (const [key, value] of Object.entries(maximalEnvironment())) {
    if (!savedEnv.has(key)) savedEnv.set(key, process.env[key]);
    process.env[key] = value;
  }

  // Imported after the environment is set: `config/env.ts` parses it at load.
  const { app } = await import('./app');
  const instance = Fastify({ logger: false, routerOptions: { ignoreTrailingSlash: true } });
  instance.setValidatorCompiler(validatorCompiler);
  instance.setSerializerCompiler(serializerCompiler);
  await instance.register(async (scope) => {
    scope.addHook('onRoute', (route) => {
      routes.push(route);
    });
    await app(scope, { defaultRealmBoot: false, realmLookup });
  });
  await instance.ready();
  server = instance;
}, 180_000);

afterAll(async () => {
  await server?.close();
  for (const [key, value] of savedEnv) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe('route surface classes of the assembled app (#486)', () => {
  it('boots with the switch-gated routes registered', () => {
    const urls = new Set(routes.map((route) => route.url));
    for (const url of [
      '/oid4vp/response',
      '/ui/wallet-login',
      '/auth/link/wallet',
      '/.well-known/assetlinks.json',
      '/.well-known/ssf-configuration',
      '/ssf/stream',
      '/ssf/jwks.json',
      '/metrics',
      '*',
    ]) {
      expect(urls, url).toContain(url);
    }
  });

  it('gives every route a surface class', () => {
    const problems = routes.map((route) => routeSurfaceProblem(route)).filter(Boolean);
    expect(problems).toEqual([]);
  });

  it('classes exactly the browser-session routes as browser', () => {
    for (const route of routes) {
      const surface = route.config?.surface;
      const label = `${String(route.method)} ${route.url}`;
      if (isBrowserSessionRoute(route)) {
        expect(surface, label).toBe('browser');
      } else {
        expect(surface, label).not.toBe('browser');
      }
    }
  });

  it('classes /health, and nothing else, as none', () => {
    const none = routes.filter((route) => route.config?.surface === 'none');
    expect(new Set(none.map((route) => route.url))).toEqual(new Set(['/health']));
  });
});

describe('error formats of the assembled app (#513)', () => {
  /** `METHOD /url` for each method a route serves; HEAD routes are Fastify's own. */
  function operations(route: RouteOptions): string[] {
    return [route.method]
      .flat()
      .filter((method) => method !== 'HEAD')
      .map((method) => `${method} ${route.url}`);
  }

  it('sets the oauth format on every OAuth protocol endpoint', () => {
    const oauth = routes
      .filter((route) => route.config?.errorFormat === 'oauth')
      .flatMap(operations);
    expect(new Set(oauth)).toEqual(OAUTH_PROTOCOL_ENDPOINTS);
  });

  it('leaves every other route on the problem default, never naming it', () => {
    for (const route of routes) {
      for (const operation of operations(route)) {
        if (OAUTH_PROTOCOL_ENDPOINTS.has(operation)) continue;
        expect(route.config?.errorFormat, operation).toBeUndefined();
      }
    }
  });
});

/** The assembled app, booted in `beforeAll`. */
function booted(): FastifyInstance {
  if (server === undefined) throw new Error('the app did not boot');
  return server;
}

/** The `Access-Control-*` header fields of an answer. */
function corsHeaders(response: LightMyRequestResponse): string[] {
  return Object.keys(response.headers).filter((name) => name.startsWith('access-control-'));
}

/** A path a route's URL pattern serves: each parameter, and a wildcard, becomes `x`. */
function concretePath(url: string): string {
  return url
    .split('/')
    .map((segment) => (segment === '*' || segment.includes(':') ? 'x' : segment))
    .join('/');
}

/** A CORS preflight from {@link SPA_ORIGIN}, announcing `method`. */
function preflight(url: string, method: string): Promise<LightMyRequestResponse> {
  return booted().inject({
    method: 'OPTIONS',
    url,
    headers: { origin: SPA_ORIGIN, 'access-control-request-method': method },
  });
}

describe('no CORS on the browser surface of the assembled app (#930)', () => {
  it('leaves every browser route, and only those, out of CORS', () => {
    for (const route of routes) {
      const label = `${String(route.method)} ${route.url}`;
      expect(route.config?.cors, label).toBe(
        route.config?.surface === 'browser' ? false : undefined
      );
    }
  });

  it('answers no preflight for a browser route, and a preflight for every other route', async () => {
    for (const route of routes) {
      // @fastify/cors's own `OPTIONS *`, which answers the preflights.
      if (route.url === '*') continue;
      for (const method of [route.method].flat()) {
        const label = `${method} ${route.url}`;
        const response = await preflight(concretePath(route.url), method);
        if (route.config?.surface === 'browser') {
          expect(response.statusCode, label).toBe(404);
          expect(response.json(), label).toMatchObject({ code: 'not_found' });
          expect(corsHeaders(response), label).toEqual([]);
        } else {
          expect(response.statusCode, label).toBe(204);
          expect(response.headers['access-control-allow-origin'], label).toBe(SPA_ORIGIN);
        }
      }
    }
  });
});

describe('the authorization endpoint answers no CORS (OAuth 2.1 draft-17 §3.1)', () => {
  it('answers no preflight for /oauth/authorize with CORS_ORIGIN set', async () => {
    for (const method of ['GET', 'POST']) {
      const response = await preflight('/oauth/authorize', method);
      expect(response.statusCode, method).toBe(404);
      expect(response.headers['access-control-allow-origin'], method).toBeUndefined();
      expect(corsHeaders(response), method).toEqual([]);
    }
  });

  it('sends no Access-Control-Allow-Origin from GET or POST /oauth/authorize', async () => {
    const get = await booted().inject({
      method: 'GET',
      url: '/oauth/authorize',
      headers: { origin: SPA_ORIGIN },
    });
    const post = await booted().inject({
      method: 'POST',
      url: '/oauth/authorize',
      headers: { origin: SPA_ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
      payload: '',
    });
    for (const [label, response] of [
      ['GET', get],
      ['POST', post],
    ] as const) {
      // The endpoint itself answered: its schema refused the empty request.
      expect(response.statusCode, label).toBe(400);
      expect(response.json(), label).toMatchObject({ error: 'invalid_request' });
      expect(response.headers['access-control-allow-origin'], label).toBeUndefined();
      expect(corsHeaders(response), label).toEqual([]);
    }
  });
});

describe('the token endpoint keeps CORS for a browser-based application (#930)', () => {
  it('answers the preflight and the call from an origin CORS_ORIGIN lists', async () => {
    const response = await preflight('/oauth/token', 'POST');
    expect(response.statusCode).toBe(204);
    expect(response.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);

    const token = await booted().inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { origin: SPA_ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
      payload: '',
    });
    expect(token.statusCode).toBe(400);
    expect(token.json()).toMatchObject({ error: 'invalid_request' });
    expect(token.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);
  });
});
