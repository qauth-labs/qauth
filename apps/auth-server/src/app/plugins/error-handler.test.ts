import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

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
});
