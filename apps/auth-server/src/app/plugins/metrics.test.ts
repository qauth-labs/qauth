import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    METRICS_ENABLED: true,
    REQUEST_ID_HEADER: 'x-request-id',
  },
}));

import metricsRoute from '../routes/metrics';
import metricsPlugin from './metrics';
import requestIdPlugin from './request-id';

async function buildApp(): Promise<FastifyInstance> {
  const app = Fastify({
    logger: false,
    requestIdHeader: 'x-request-id',
    requestIdLogLabel: 'reqId',
    genReqId: () => 'generated-id',
  });
  await app.register(requestIdPlugin);
  await app.register(metricsPlugin);
  await app.register(metricsRoute);
  return app;
}

describe('metrics + request-id', () => {
  it('exposes /metrics in Prometheus text format with the auth counters', async () => {
    const app = await buildApp();

    // Drive the counters so they appear in the output.
    app.metrics.loginAttempts.inc({ result: 'success' });
    app.metrics.loginAttempts.inc({ result: 'failure', reason: 'invalid_credentials' });
    app.metrics.tokensIssued.inc({ type: 'access', grant_type: 'password' });
    app.metrics.tokensIssued.inc({ type: 'refresh', grant_type: 'password' });

    const res = await app.inject({ method: 'GET', url: '/metrics' });

    expect(res.statusCode).toBe(200);
    expect(res.headers['content-type']).toContain('text/plain');
    expect(res.body).toContain('qauth_login_attempts_total');
    expect(res.body).toContain('qauth_tokens_issued_total');
    expect(res.body).toContain('result="success"');
    expect(res.body).toContain('type="access"');
    expect(res.body).toContain('grant_type="password"');
    // HELP/TYPE lines prove Prometheus exposition format.
    expect(res.body).toContain('# HELP qauth_login_attempts_total');
    expect(res.body).toContain('# TYPE qauth_login_attempts_total counter');

    await app.close();
  });

  it('generates a request id and echoes it on the response header', async () => {
    const app = await buildApp();
    app.get('/ping', async () => ({ ok: true }));

    const res = await app.inject({ method: 'GET', url: '/ping' });

    expect(res.statusCode).toBe(200);
    expect(res.headers['x-request-id']).toBe('generated-id');

    await app.close();
  });

  it('propagates an incoming X-Request-Id onto the response', async () => {
    const app = await buildApp();
    app.get('/ping', async () => ({ ok: true }));

    const res = await app.inject({
      method: 'GET',
      url: '/ping',
      headers: { 'x-request-id': 'caller-supplied-id' },
    });

    expect(res.headers['x-request-id']).toBe('caller-supplied-id');

    await app.close();
  });
});
