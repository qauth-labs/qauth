import swagger from '@fastify/swagger';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import {
  familyDocument,
  familyDocumentPath,
  familyTokenSecurity,
  type OpenApiDocument,
} from '../api-conventions/family-documents';
import { openapiOptions } from '../openapi-options';
import familyDocumentRoutes from './family-documents';

/**
 * The account and developer APIs serve their own OpenAPI documents (#525) at
 * `<prefix>/openapi.json`, cut from the server's document. The routes alone
 * are registered, beside one route of each family: no database, no Redis.
 */

let app: FastifyInstance | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

async function buildApp({ withSwagger = true } = {}): Promise<FastifyInstance> {
  const server = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);
  if (withSwagger) await server.register(swagger, openapiOptions);
  for (const [family, resource] of [
    ['account', 'consents'],
    ['developer', 'clients'],
  ] as const) {
    server.get(
      `/${family}/v1-rc.0/${resource}`,
      {
        schema: {
          operationId: `${family}.${resource}.list`,
          security: familyTokenSecurity(),
          'x-qauth-stability': 'stable',
          response: { 200: z.object({ items: z.array(z.string()) }) },
        },
      },
      async () => ({ items: [] })
    );
  }
  await server.register(familyDocumentRoutes);
  await server.ready();
  app = server;
  return server;
}

describe('GET <prefix>/openapi.json on the public listener', () => {
  it.each(['account', 'developer'] as const)(
    "serves the %s family's document, cut from the server's",
    async (family) => {
      const server = await buildApp();
      const response = await server.inject({ method: 'GET', url: familyDocumentPath(family) });
      expect(response.statusCode).toBe(200);
      expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
      expect(response.headers['cache-control']).toBe('public, max-age=3600');
      const document = response.json<OpenApiDocument>();
      expect(document).toEqual(familyDocument(server.swagger() as OpenApiDocument, family));
      expect(document.info).toMatchObject({ version: 'v1-rc.0' });
      expect(Object.keys(document.paths ?? {})).toEqual([
        family === 'account' ? '/account/v1-rc.0/consents' : '/developer/v1-rc.0/clients',
      ]);
    }
  );

  it('is in no document: it describes the operations and is none of them', async () => {
    const server = await buildApp();
    const paths = Object.keys((server.swagger() as OpenApiDocument).paths ?? {});
    expect(paths).not.toContain(familyDocumentPath('account'));
    expect(paths).not.toContain(familyDocumentPath('developer'));
  });

  it('serves no admin document: that one is on the admin listener', async () => {
    const server = await buildApp();
    expect(
      (await server.inject({ method: 'GET', url: familyDocumentPath('admin') })).statusCode
    ).toBe(404);
  });

  it('answers 404 on a process that collects no OpenAPI document', async () => {
    const server = await buildApp({ withSwagger: false });
    const response = await server.inject({ method: 'GET', url: familyDocumentPath('account') });
    expect(response.statusCode).toBe(404);
  });

  it('are meta routes: documents about the server, on every host of the realm', async () => {
    const routes: Array<[string, unknown]> = [];
    const server = Fastify({ logger: false });
    app = server;
    server.addHook('onRoute', (route) => {
      // The GET routes; Fastify adds a HEAD route beside each.
      if (route.method === 'GET') routes.push([route.url, route.config?.surface]);
    });
    await server.register(familyDocumentRoutes);
    expect(routes).toEqual([
      ['/account/v1-rc.0/openapi.json', 'meta'],
      ['/developer/v1-rc.0/openapi.json', 'meta'],
    ]);
  });
});
