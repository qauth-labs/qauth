import { JWTExpiredError } from '@qauth/shared-errors';
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
});
