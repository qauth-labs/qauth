import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';

// The event emitter's module imports `config/env`, which validates required
// env at module load. Stub it so the unit run needs no real environment.
vi.mock('../../../config/env', () => ({
  env: {
    DATABASE_URL: 'postgresql://test:test@localhost:5432/test',
    EMAIL_FROM_ADDRESS: 'noreply@example.com',
    EMAIL_BASE_URL: 'http://localhost:3000',
    DEFAULT_REALM_NAME: 'master',
  },
}));

import ssfRoutes from './index';

/**
 * `GET /ssf/jwks.json`, the SSF transmitter's own JWKS (#410, d-1026-09): the
 * realm's SET verification keys, apart from the realm JWKS. The end-to-end
 * suite verifies a pushed SET against it; this one pins the route's own rules.
 */

const REALM_ID = '0192a000-0000-7000-8000-000000000001';
const EVENT_KEY = { kty: 'OKP', crv: 'Ed25519', x: 'event-x', alg: 'EdDSA', kid: 'event' };

const apps: FastifyInstance[] = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

async function buildApp(
  options: {
    switchOn?: boolean;
    getVerificationKeys?: (...args: unknown[]) => Promise<unknown>;
  } = {}
) {
  const app = Fastify({ logger: false });
  apps.push(app);
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  const getVerificationKeys = vi.fn(
    options.getVerificationKeys ??
      (async () => [{ kid: 'event', status: 'active', publicJwk: EVENT_KEY }])
  );
  const requireJwt = vi.fn();
  app.decorate('ssf', {} as never);
  app.decorate('signer', { getVerificationKeys } as unknown as never);
  app.decorate('repositories', { ssfStreams: {} } as unknown as never);
  app.decorate('requireJwt', requireJwt as never);
  app.decorateRequest('realm', null);
  app.addHook('onRequest', async (request) => {
    request.realm = {
      id: REALM_ID,
      issuer: 'https://auth.example.com',
      ssfTransmitterEnabled: options.switchOn ?? true,
    } as never;
  });
  await app.register(ssfRoutes, { prefix: '/ssf' });
  await app.ready();
  return { app, getVerificationKeys, requireJwt };
}

describe('GET /ssf/jwks.json', () => {
  it("serves the realm's SET keys to anyone, cacheable for five minutes", async () => {
    const { app, getVerificationKeys, requireJwt } = await buildApp();

    const res = await app.inject({ method: 'GET', url: '/ssf/jwks.json' });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toBe('application/jwk-set+json; charset=utf-8');
    expect(res.headers['cache-control']).toBe('public, max-age=300');
    expect(res.json()).toEqual({ keys: [EVENT_KEY] });
    expect(getVerificationKeys).toHaveBeenCalledWith('api', REALM_ID, 'event_signing');
    // No receiver token is asked for.
    expect(requireJwt).not.toHaveBeenCalled();
  });

  it('answers as an unknown route does for a realm that does not run the transmitter', async () => {
    const { app, getVerificationKeys } = await buildApp({ switchOn: false });

    const res = await app.inject({ method: 'GET', url: '/ssf/jwks.json' });

    // The `not_found` problem document of a path no route serves (#513).
    expect(res.statusCode).toBe(404);
    expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
    expect(res.json()).toEqual({
      type: 'https://docs.qauth.dev/reference/problem-types/#not-found',
      title: 'Not found',
      status: 404,
      detail: 'No route serves GET /ssf/jwks.json.',
      instance: '/ssf/jwks.json',
      code: 'not_found',
      trace_id: expect.any(String),
    });
    expect(getVerificationKeys).not.toHaveBeenCalled();
  });

  it('fails when the key store cannot be read, rather than serve no key', async () => {
    const { app } = await buildApp({
      getVerificationKeys: async () => {
        throw new Error('the key store is down');
      },
    });

    const res = await app.inject({ method: 'GET', url: '/ssf/jwks.json' });

    expect(res.statusCode).toBe(500);
  });
});
