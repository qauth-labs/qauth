/**
 * EVERY ROUTE OF THE ASSEMBLED APP HAS A SURFACE CLASS (#486).
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
 * as they register, and no request is sent.
 */
import { generateKeyPairSync } from 'node:crypto';

import Fastify, { type FastifyInstance, type RouteOptions } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { routeSurfaceProblem } from './helpers/route-surface';

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

/** The routes that read or set the browser session cookie. */
function isBrowserSessionRoute(url: string): boolean {
  return (
    url.startsWith('/ui/') ||
    url === '/oauth/authorize' ||
    url === '/consents' ||
    url.startsWith('/consents/') ||
    url === '/auth/link/wallet' ||
    url.startsWith('/auth/link/wallet/')
  );
}

let server: FastifyInstance | undefined;
/** Every route as it registered; read after the boot, once every `onRoute` hook ran. */
const routes: RouteOptions[] = [];
const savedEnv = new Map<string, string | undefined>();

beforeAll(async () => {
  for (const key of Object.keys(process.env)) {
    if (/^(OID4VP_|WALLET_|ACR_|WEBAUTHN_)/.test(key)) {
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
    await app(scope, { defaultRealmBoot: false, realmLookup: async () => undefined });
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
      if (isBrowserSessionRoute(route.url)) {
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
