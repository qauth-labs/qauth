import {
  INTERACTION_OPENAPI,
  INTERACTION_OPENAPI_PATH,
  INTERACTION_PROBLEM_CODES,
  STATUS_TITLES,
} from '@qauth-labs/shared-interaction-contract';
import Fastify from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { PROBLEM_CODES, statusTitle } from '../api-conventions/problem';
import interactionDocumentRoute from './interaction-document';

/**
 * The auth server serves the Interaction API contract at a fixed path (#590).
 * The route alone is registered: no database, no Redis.
 */

let app: ReturnType<typeof Fastify> | undefined;

afterEach(async () => {
  await app?.close();
  app = undefined;
});

async function buildApp() {
  app = Fastify({ logger: false });
  await app.register(interactionDocumentRoute);
  return app;
}

describe('GET /interaction/v1-rc.0/openapi.json', () => {
  it('serves the contract document, as the contract library builds it', async () => {
    const response = await (
      await buildApp()
    ).inject({ method: 'GET', url: INTERACTION_OPENAPI_PATH });
    expect(response.statusCode).toBe(200);
    expect(response.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(response.headers['cache-control']).toBe('public, max-age=3600');
    expect(response.json()).toEqual(INTERACTION_OPENAPI);
    expect(response.json()).toMatchObject({
      openapi: expect.stringMatching(/^3\.1\./),
      info: { version: 'v1-rc.0' },
    });
  });

  it('is served at the path the contract names, written out for the endpoint-coverage guard', async () => {
    const server = await buildApp();
    expect(INTERACTION_OPENAPI_PATH).toBe('/interaction/v1-rc.0/openapi.json');
    expect(server.hasRoute({ method: 'GET', url: INTERACTION_OPENAPI_PATH })).toBe(true);
  });

  it('is a meta route: a document about the server, on every host of the realm', async () => {
    const routes: Array<[string, unknown]> = [];
    const server = Fastify({ logger: false });
    app = server;
    server.addHook('onRoute', (route) => {
      routes.push([String(route.method), route.config?.surface]);
    });
    await server.register(interactionDocumentRoute);
    await server.ready();
    // Fastify adds a HEAD route beside the GET; both are `meta`.
    expect(routes).toEqual([
      ['GET', 'meta'],
      ['HEAD', 'meta'],
    ]);
  });
});

describe('the Interaction API problem codes', () => {
  // The contract names the codes its errors carry; the error handler sends only
  // codes the server's registry publishes, with the status listed there.
  it('are published in the server’s problem registry, each with the same status', () => {
    for (const [code, entry] of Object.entries(INTERACTION_PROBLEM_CODES)) {
      expect(PROBLEM_CODES[code as keyof typeof PROBLEM_CODES]?.status, code).toBe(entry.status);
    }
  });

  // The contract's examples and descriptions name the `title` the error handler
  // sends, which is Node's status phrase (413 is still "Payload Too Large").
  it('name the status phrase the error handler sends as title', () => {
    for (const { status } of Object.values(INTERACTION_PROBLEM_CODES)) {
      expect(STATUS_TITLES[status], String(status)).toBe(statusTitle(status));
    }
  });
});
