import rateLimit from '@fastify/rate-limit';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { realmRateLimitKey } from '../../helpers/realm-rate-limit';
import { UI_ASSET_FILES, UI_STYLESHEET_URL, uiAsset } from '../../helpers/ui-assets';
import assetRoutes, { ASSET_RATE_LIMIT } from './ui';

/**
 * `GET /assets/ui/<file>` (#472): the stylesheet and the fonts, each with a
 * year's immutable cache, a 400 for a name of another shape, the app's 404
 * for every other name, and a rate-limit bucket of its own.
 */

/** The test app: the asset route under `/assets`, and a 404 handler of the app's shape. */
async function buildApp(options: { readonly globalMax?: number } = {}): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  if (options.globalMax !== undefined) {
    // The global bucket, as plugins/rate-limit.ts registers it (in memory here).
    await app.register(rateLimit, {
      max: options.globalMax,
      timeWindow: 60_000,
      keyGenerator: realmRateLimitKey,
    });
  }
  app.setNotFoundHandler(async (_request, reply) => reply.code(404).send({ code: 'not_found' }));
  // A page on the global bucket, as `GET /ui/login` is.
  app.get('/ui/login', async () => 'page');
  await app.register(assetRoutes, { prefix: '/assets' });
  await app.ready();
  return app;
}

describe('GET /assets/ui/:file (#472)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp();
  });

  afterAll(async () => {
    await app.close();
  });

  it('serves the stylesheet the pages link, outside /ui/, cacheable for a year', async () => {
    expect(UI_STYLESHEET_URL).toMatch(/^\/assets\/ui\/qauth-[0-9a-f]{8}\.css$/);
    const response = await app.inject({ method: 'GET', url: UI_STYLESHEET_URL });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe('text/css; charset=utf-8');
    expect(response.headers['cache-control']).toBe('public, max-age=31536000, immutable');
    expect(response.rawPayload.equals(uiAsset(UI_ASSET_FILES[0])?.body ?? Buffer.alloc(0))).toBe(
      true
    );
  });

  it('serves every font the stylesheet names, as woff2', async () => {
    for (const name of UI_ASSET_FILES.slice(1)) {
      const response = await app.inject({ method: 'GET', url: `/assets/ui/${name}` });

      expect(response.statusCode, name).toBe(200);
      expect(response.headers['content-type'], name).toBe('font/woff2');
      expect(response.headers['cache-control'], name).toBe('public, max-age=31536000, immutable');
      expect(response.rawPayload.equals(uiAsset(name)?.body ?? Buffer.alloc(0)), name).toBe(true);
    }
  });

  it('answers HEAD with the headers and no body', async () => {
    const response = await app.inject({ method: 'HEAD', url: UI_STYLESHEET_URL });

    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe('text/css; charset=utf-8');
    expect(response.body).toBe('');
  });

  it.each([
    '/assets/ui/qauth-00000000.css',
    '/assets/ui/dm-sans-latin-wght-normal.woff2',
    `/assets/ui/fonts/${UI_ASSET_FILES[1]}`,
    `/ui/assets/${UI_ASSET_FILES[0]}`,
  ])('answers the app’s 404 for %s', async (url) => {
    const response = await app.inject({ method: 'GET', url });

    expect(response.statusCode, url).toBe(404);
    expect(response.json(), url).toEqual({ code: 'not_found' });
    expect(response.headers['cache-control'], url).toBeUndefined();
  });

  it.each([
    '/assets/ui/..%2Fpackage.json',
    '/assets/ui/%2E%2E%2F%2E%2E%2Fpackage.json',
    '/assets/ui/constructor',
    '/assets/ui/__proto__',
    '/assets/ui/QAUTH-00000000.CSS',
    '/assets/ui/qauth-00000000.css.map',
    `/assets/ui/${'a'.repeat(93)}.css`,
    '/assets/ui/',
  ])('refuses %s, a name of no served shape, before it looks anything up', async (url) => {
    const response = await app.inject({ method: 'GET', url });

    expect(response.statusCode, url).toBe(400);
    expect(response.headers['cache-control'], url).toBeUndefined();
  });
});

describe('the asset route’s rate-limit bucket (#472)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildApp({ globalMax: 2 });
  });

  afterAll(async () => {
    await app.close();
  });

  it('never spends the global bucket the sign-in pages share', async () => {
    for (let i = 0; i < 10; i++) {
      const response = await app.inject({ method: 'GET', url: UI_STYLESHEET_URL });
      expect(response.statusCode).toBe(200);
    }
    // The page still has its whole budget of two.
    expect((await app.inject({ method: 'GET', url: '/ui/login' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/ui/login' })).statusCode).toBe(200);
    expect((await app.inject({ method: 'GET', url: '/ui/login' })).statusCode).toBe(429);
  });

  it('keeps a bucket of its own, refused past its ceiling', async () => {
    const fresh = await buildApp({ globalMax: 2 });
    try {
      const statuses: number[] = [];
      for (let i = 0; i <= ASSET_RATE_LIMIT.max; i++) {
        statuses.push((await fresh.inject({ method: 'GET', url: UI_STYLESHEET_URL })).statusCode);
      }
      expect(statuses.slice(0, ASSET_RATE_LIMIT.max).every((status) => status === 200)).toBe(true);
      expect(statuses[ASSET_RATE_LIMIT.max]).toBe(429);
    } finally {
      await fresh.close();
    }
  });
});
