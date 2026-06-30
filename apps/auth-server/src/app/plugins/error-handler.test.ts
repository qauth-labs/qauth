import {
  ForbiddenError,
  InvalidClientError,
  JWTExpiredError,
  JWTInvalidError,
  UniqueConstraintError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

// F-05: error-handler now reads the validated `env.NODE_ENV` instead of the
// raw `process.env.NODE_ENV`. Mock the env module so the test doesn't trigger
// full env parsing (DATABASE_URL etc. are not set in the test environment).
vi.mock('../../config/env', () => ({
  env: {
    NODE_ENV: 'development',
  },
}));

import errorHandler from './error-handler';

async function buildTestApp(): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(errorHandler);

  app.get('/test-jwt-expired', async () => {
    throw new JWTExpiredError('JWT token has expired');
  });

  app.get('/test-jwt-invalid', async () => {
    throw new JWTInvalidError('Invalid JWT token');
  });

  app.post('/test-invalid-client', async () => {
    throw new InvalidClientError();
  });

  app.post('/test-forbidden', async () => {
    throw new ForbiddenError('Static API keys are disabled for production clients.');
  });

  app.post('/test-unique-constraint', async () => {
    // The DB layer surfaces the offending constraint name; the handler must NOT
    // leak it (account-enumeration oracle, e.g. duplicate-email registration).
    throw new UniqueConstraintError('users_email_realm_key');
  });

  return app;
}

describe('error-handler plugin', () => {
  it('maps JWTExpiredError to 401 response', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/test-jwt-expired',
    });

    expect(response.statusCode).toBe(401);

    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      error: 'JWT token has expired',
      code: 'JWT_EXPIRED',
    });

    await app.close();
  });

  it('maps JWTInvalidError to 401 response', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/test-jwt-invalid',
    });

    expect(response.statusCode).toBe(401);

    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      error: 'Invalid JWT token',
      code: 'JWT_INVALID',
    });

    await app.close();
  });

  it('maps ForbiddenError to a 403 response (ADR-008 static-API-key gate)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({ method: 'POST', url: '/test-forbidden' });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toMatchObject({
      statusCode: 403,
      error: 'Static API keys are disabled for production clients.',
      code: 'FORBIDDEN',
    });

    await app.close();
  });

  it('sets WWW-Authenticate: Basic on InvalidClientError when request used Basic auth (RFC 6749 §5.2)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/test-invalid-client',
      headers: {
        authorization: `Basic ${Buffer.from('cid:bad').toString('base64')}`,
      },
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBe('Basic realm="OAuth"');
    expect(response.json()).toMatchObject({
      error: 'invalid_client',
      code: 'INVALID_CLIENT',
      statusCode: 401,
    });

    await app.close();
  });

  it('omits WWW-Authenticate on InvalidClientError when request did not use Basic auth', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/test-invalid-client',
    });

    expect(response.statusCode).toBe(401);
    expect(response.headers['www-authenticate']).toBeUndefined();
    expect(response.json()).toMatchObject({
      error: 'invalid_client',
      code: 'INVALID_CLIENT',
      statusCode: 401,
    });

    await app.close();
  });

  it('does not leak the constraint name on UniqueConstraintError (enumeration defence)', async () => {
    const app = await buildTestApp();

    const response = await app.inject({
      method: 'POST',
      url: '/test-unique-constraint',
    });

    expect(response.statusCode).toBe(409);

    const json = response.json();
    // Code + status preserved so legitimate clients can branch on the conflict.
    expect(json).toMatchObject({
      error: 'Resource already exists',
      code: 'UNIQUE_CONSTRAINT_VIOLATION',
      statusCode: 409,
    });
    // The constraint name must NOT appear anywhere in the response — not as a
    // dedicated field, and not embedded in the generic error message.
    expect(json.constraint).toBeUndefined();
    expect(JSON.stringify(json)).not.toContain('users_email_realm_key');

    await app.close();
  });
});
