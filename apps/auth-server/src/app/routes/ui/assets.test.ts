import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { UI_ASSET_FILES, UI_STYLESHEET_URL, uiAsset } from '../../helpers/ui-assets';
import assetRoutes from './assets';

/**
 * `GET /ui/assets/<file>` (#472): the stylesheet and the fonts, each with a
 * year's immutable cache, and the app's 404 for every other name.
 */
describe('GET /ui/assets/:file (#472)', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = Fastify({ logger: false });
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    app.setNotFoundHandler(async (_request, reply) => reply.code(404).send({ code: 'not_found' }));
    await app.register(assetRoutes, { prefix: '/ui' });
    await app.ready();
  });

  afterAll(async () => {
    await app.close();
  });

  it('serves the stylesheet the pages link, cacheable for a year', async () => {
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
      const response = await app.inject({ method: 'GET', url: `/ui/assets/${name}` });

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
    '/ui/assets/qauth-00000000.css',
    '/ui/assets/dm-sans-latin-wght-normal.woff2',
    '/ui/assets/..%2Fpackage.json',
    '/ui/assets/%2E%2E%2F%2E%2E%2Fpackage.json',
    '/ui/assets/constructor',
    '/ui/assets/__proto__',
    `/ui/assets/fonts/${UI_ASSET_FILES[1]}`,
    '/ui/assets/',
  ])('answers the app’s 404 for %s', async (url) => {
    const response = await app.inject({ method: 'GET', url });

    expect(response.statusCode, url).toBe(404);
    expect(response.json(), url).toEqual({ code: 'not_found' });
    expect(response.headers['cache-control'], url).toBeUndefined();
  });
});
