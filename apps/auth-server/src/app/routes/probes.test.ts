import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    SERVICE_ROLES: ['api'],
    RATE_LIMIT_ENABLED: true,
    HEALTH_RATE_LIMIT_MAX: 3,
    HEALTH_RATE_LIMIT_WINDOW: 60,
  },
}));

import { createReadinessRegistry, type ReadinessRegistry } from '../helpers/readiness';
import healthRoute from './health';
import readyRoute from './ready';

/**
 * GET /health AND GET /ready (#500), on a bare Fastify: what each answers,
 * its headers, and its in-process rate limit. The assembled app runs them in
 * `health-readiness.integration.test.ts`.
 */

const apps: FastifyInstance[] = [];

afterEach(async () => {
  for (const app of apps.splice(0)) await app.close();
});

async function buildApp(readiness: ReadinessRegistry = createReadinessRegistry()) {
  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  app.decorate('readiness', readiness);
  await app.register(healthRoute);
  await app.register(readyRoute);
  apps.push(app);
  return app;
}

describe('GET /health', () => {
  it('answers 200 with the roles, checking nothing, and is never stored', async () => {
    const readiness = createReadinessRegistry();
    const run = vi.fn(async () => {
      throw new Error('down');
    });
    readiness.register({ name: 'database', run });
    const app = await buildApp(readiness);

    const res = await app.inject({ method: 'GET', url: '/health' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok', timestamp: expect.any(String), roles: ['api'] });
    expect(res.headers['cache-control']).toBe('no-store');
    expect(run).not.toHaveBeenCalled();
  });

  it('limits each client address in memory, with the rate-limit headers', async () => {
    const app = await buildApp();
    for (let sent = 1; sent <= 3; sent += 1) {
      const res = await app.inject({ method: 'GET', url: '/health' });
      expect(res.statusCode).toBe(200);
      expect(res.headers['x-ratelimit-limit']).toBe('3');
      expect(res.headers['x-ratelimit-remaining']).toBe(String(3 - sent));
    }
    const refused = await app.inject({ method: 'GET', url: '/health' });
    expect(refused.statusCode).toBe(429);
    expect(Number(refused.headers['retry-after'])).toBeGreaterThan(0);
    // Another address is not limited by this one's requests.
    const other = await app.inject({ method: 'GET', url: '/health', remoteAddress: '10.0.0.9' });
    expect(other.statusCode).toBe(200);
  });
});

describe('GET /ready', () => {
  it('answers 200 with each check when every one passes', async () => {
    const readiness = createReadinessRegistry();
    readiness.register({ name: 'database', run: async () => undefined });
    const app = await buildApp(readiness);

    const res = await app.inject({ method: 'GET', url: '/ready' });

    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      status: 'ok',
      roles: ['api'],
      checks: { database: { status: 'ok' } },
    });
    expect(res.headers['cache-control']).toBe('no-store');
  });

  it('answers 503 with a problem document naming the check that failed, and why, never the error', async () => {
    const readiness = createReadinessRegistry();
    readiness.register({ name: 'database', run: async () => undefined });
    readiness.register({
      name: 'redis',
      run: async () => {
        throw new Error('connect ECONNREFUSED 10.1.2.3:6379');
      },
    });
    readiness.register({ name: 'slow', run: () => new Promise(() => undefined), timeoutMs: 10 });
    const app = await buildApp(readiness);

    const res = await app.inject({ method: 'GET', url: '/ready' });

    expect(res.statusCode).toBe(503);
    // A problem document (ADR-019 Decision 7), with the checks as extension members.
    expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
    expect(res.json()).toEqual({
      type: 'https://docs.qauth.dev/reference/problem-types/#service-unavailable',
      title: 'Service unavailable',
      status: 503,
      detail: 'A readiness check failed: redis, slow.',
      instance: '/ready',
      code: 'service_unavailable',
      trace_id: expect.any(String),
      roles: ['api'],
      checks: {
        database: { status: 'ok' },
        redis: { status: 'fail', reason: 'error' },
        slow: { status: 'fail', reason: 'timeout' },
      },
    });
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).not.toContain('ECONNREFUSED');
  });

  it('counts its own limit apart from /health', async () => {
    const app = await buildApp();
    for (let sent = 0; sent < 3; sent += 1) {
      expect((await app.inject({ method: 'GET', url: '/health' })).statusCode).toBe(200);
    }
    expect((await app.inject({ method: 'GET', url: '/ready' })).statusCode).toBe(200);
  });
});

describe('the probes with RATE_LIMIT_ENABLED=false', () => {
  it('count nothing, as no other route does', async () => {
    const { probeRateLimitHook } = await import('../helpers/probe-routes');
    const app = Fastify({ logger: false });
    apps.push(app);
    app.get(
      '/probe',
      { onRequest: probeRateLimitHook({ max: 1, windowSeconds: 60, enabled: false }) },
      async () => ({ ok: true })
    );
    for (let sent = 0; sent < 3; sent += 1) {
      const res = await app.inject({ method: 'GET', url: '/probe' });
      expect(res.statusCode).toBe(200);
      expect(res.headers['x-ratelimit-limit']).toBeUndefined();
    }
  });
});
