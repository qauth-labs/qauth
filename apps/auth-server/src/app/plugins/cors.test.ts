/**
 * The CORS plugin (`plugins/cors.ts`, #930): `@fastify/cors` with the origins
 * of `CORS_ORIGIN`, and no CORS on the `browser` routes in any environment.
 *
 * A stub app with one route per case, registered as `app.ts` registers them:
 * the plugin first, then the routes, some under a prefix. What the assembled
 * app does with its real routes is checked in `route-surfaces.test.ts`.
 */
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import type { RouteSurface } from '../helpers/route-surface';
import { type CorsPluginOptions, corsOriginOption, corsPlugin } from './cors';

const SPA_ORIGIN = 'https://spa.example.com';

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

/** The routes of the stub app, and the surface each names. */
const ROUTES: readonly { method: 'GET' | 'POST'; url: string; surface: RouteSurface }[] = [
  { method: 'GET', url: '/oauth/authorize', surface: 'browser' },
  { method: 'POST', url: '/oauth/authorize', surface: 'browser' },
  { method: 'POST', url: '/oauth/token', surface: 'api' },
  // The verification page and the JSON API share a path.
  { method: 'GET', url: '/auth/verify', surface: 'browser' },
  { method: 'POST', url: '/auth/verify', surface: 'api' },
  { method: 'GET', url: '/.well-known/openid-configuration', surface: 'meta' },
];

async function buildApp(options: CorsPluginOptions): Promise<FastifyInstance> {
  const instance = Fastify({ logger: false, routerOptions: { ignoreTrailingSlash: true } });
  await instance.register(async (scope) => {
    await scope.register(corsPlugin, options);
    for (const { method, url, surface } of ROUTES) {
      scope.route({ method, url, config: { surface }, handler: async () => ({ url }) });
    }
    // Under a prefix, with a parameter, as the route manifest registers `/ui/*`.
    await scope.register(
      async (ui) => {
        ui.get('/resume/:handle', { config: { surface: 'browser' } }, async () => ({ ui: true }));
      },
      { prefix: '/ui' }
    );
  });
  await instance.ready();
  app = instance;
  return instance;
}

function preflight(url: string, method?: string): Promise<LightMyRequestResponse> {
  return app!.inject({
    method: 'OPTIONS',
    url,
    headers: {
      origin: SPA_ORIGIN,
      ...(method === undefined ? {} : { 'access-control-request-method': method }),
    },
  });
}

function call(method: 'GET' | 'POST', url: string): Promise<LightMyRequestResponse> {
  return app!.inject({ method, url, headers: { origin: SPA_ORIGIN } });
}

/** The `Access-Control-*` header fields of an answer. */
function corsHeaders(response: LightMyRequestResponse): string[] {
  return Object.keys(response.headers).filter((name) => name.startsWith('access-control-'));
}

/** An answer as to a path no route serves: 404, the problem document, no CORS. */
function expectRefusedPreflight(response: LightMyRequestResponse, label: string): void {
  expect(response.statusCode, label).toBe(404);
  expect(response.json(), label).toMatchObject({ code: 'not_found', status: 404 });
  expect(corsHeaders(response), label).toEqual([]);
}

describe('corsOriginOption', () => {
  it('splits CORS_ORIGIN into trimmed origins and drops empty entries', () => {
    expect(
      corsOriginOption({ corsOrigin: ' https://a.example, https://b.example ,', production: true })
    ).toEqual(['https://a.example', 'https://b.example']);
  });

  it('allows no origin in production when CORS_ORIGIN is unset or empty', () => {
    expect(corsOriginOption({ production: true })).toBe(false);
    expect(corsOriginOption({ corsOrigin: ' , ', production: true })).toBe(false);
  });

  it('allows any origin outside production when CORS_ORIGIN is unset', () => {
    expect(corsOriginOption({ production: false })).toBe('*');
  });
});

describe('the CORS plugin with CORS_ORIGIN set', () => {
  const options: CorsPluginOptions = {
    corsOrigin: `${SPA_ORIGIN}, https://other.example.com`,
    production: true,
  };

  it('marks every browser route, and only those, with config.cors = false', async () => {
    const marks: Record<string, unknown> = {};
    const instance = Fastify({ logger: false });
    await instance.register(async (scope) => {
      await scope.register(corsPlugin, options);
      scope.addHook('onRoute', (route) => {
        marks[`${String(route.method)} ${route.url}`] = route.config?.cors;
      });
      for (const { method, url, surface } of ROUTES) {
        scope.route({ method, url, config: { surface }, handler: async () => ({}) });
      }
    });
    await instance.ready();
    app = instance;

    for (const { method, url, surface } of ROUTES) {
      expect(marks[`${method} ${url}`], `${method} ${url}`).toBe(
        surface === 'browser' ? false : undefined
      );
    }
  });

  it('answers no preflight for a browser route, for the method it announces', async () => {
    await buildApp(options);
    expectRefusedPreflight(await preflight('/oauth/authorize', 'GET'), 'GET /oauth/authorize');
    expectRefusedPreflight(await preflight('/oauth/authorize', 'POST'), 'POST /oauth/authorize');
    expectRefusedPreflight(await preflight('/auth/verify', 'GET'), 'GET /auth/verify');
    expectRefusedPreflight(await preflight('/ui/resume/abc', 'GET'), 'GET /ui/resume/:handle');
  });

  it('answers no OPTIONS request for a browser route that announces no method', async () => {
    await buildApp(options);
    expectRefusedPreflight(await preflight('/oauth/authorize'), 'OPTIONS /oauth/authorize');
  });

  it('answers no preflight for any spelling of the path the router serves', async () => {
    await buildApp(options);
    for (const url of [
      '/oauth/authorize/',
      '/oauth/authorize?client_id=spa&response_type=code',
      '/oauth/%61uthorize',
      '/ui/resume/abc/',
      '/ui/resume/a%2Fb',
    ]) {
      expectRefusedPreflight(await preflight(url, 'GET'), url);
    }
  });

  it('sends no Access-Control-* header from a browser route', async () => {
    await buildApp(options);
    for (const [method, url] of [
      ['GET', '/oauth/authorize'],
      ['POST', '/oauth/authorize'],
      ['GET', '/oauth/authorize/'],
      ['GET', '/oauth/%61uthorize'],
      ['GET', '/auth/verify'],
      ['GET', '/ui/resume/abc'],
    ] as const) {
      const response = await call(method, url);
      expect(response.statusCode, `${method} ${url}`).toBe(200);
      expect(corsHeaders(response), `${method} ${url}`).toEqual([]);
    }
  });

  it('keeps CORS on the routes of every other surface', async () => {
    await buildApp(options);
    const token = await call('POST', '/oauth/token');
    expect(token.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);

    const tokenPreflight = await preflight('/oauth/token', 'POST');
    expect(tokenPreflight.statusCode).toBe(204);
    expect(tokenPreflight.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);
    expect(tokenPreflight.headers['access-control-allow-methods']).toBe('GET,HEAD,POST');

    // The JSON API beside the verification page keeps its preflight.
    const verifyPreflight = await preflight('/auth/verify', 'POST');
    expect(verifyPreflight.statusCode).toBe(204);
    expect(verifyPreflight.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);
    const verify = await call('POST', '/auth/verify');
    expect(verify.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);

    const discovery = await call('GET', '/.well-known/openid-configuration');
    expect(discovery.headers['access-control-allow-origin']).toBe(SPA_ORIGIN);
  });

  it('allows no origin CORS_ORIGIN does not list', async () => {
    await buildApp(options);
    const token = await app!.inject({
      method: 'POST',
      url: '/oauth/token',
      headers: { origin: 'https://elsewhere.example.com' },
    });
    expect(token.headers['access-control-allow-origin']).toBeUndefined();
  });
});

describe('the CORS plugin outside production with CORS_ORIGIN unset', () => {
  it('allows any origin but on the browser routes', async () => {
    await buildApp({ production: false });
    expect((await call('POST', '/oauth/token')).headers['access-control-allow-origin']).toBe('*');
    expect(corsHeaders(await call('GET', '/oauth/authorize'))).toEqual([]);
    expectRefusedPreflight(await preflight('/oauth/authorize', 'GET'), 'GET /oauth/authorize');
  });
});

describe('the CORS plugin in production with CORS_ORIGIN unset', () => {
  it('allows no origin anywhere', async () => {
    await buildApp({ production: true });
    expect(corsHeaders(await call('POST', '/oauth/token'))).toEqual([]);
    expect(corsHeaders(await call('GET', '/oauth/authorize'))).toEqual([]);
    for (const url of ['/oauth/token', '/oauth/authorize']) {
      const response = await preflight(url, 'POST');
      expect(response.statusCode, url).toBe(404);
      expect(corsHeaders(response), url).toEqual([]);
    }
  });
});
