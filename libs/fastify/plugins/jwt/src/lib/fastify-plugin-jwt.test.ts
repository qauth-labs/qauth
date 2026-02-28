import { generateEdDSAKeyPair, importPrivateKey, signAccessToken } from '@qauth/server-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { exportPKCS8, exportSPKI } from 'jose';
import { describe, expect, it } from 'vitest';

import { jwtPlugin } from './fastify-plugin-jwt';

/**
 * Minimal error handler for tests - maps JWT errors to 401
 */
async function registerTestErrorHandler(app: FastifyInstance) {
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof JWTExpiredError) {
      return reply.code(401).send({
        error: error.message,
        code: 'JWT_EXPIRED',
        statusCode: 401,
      });
    }
    if (error instanceof JWTInvalidError) {
      return reply.code(401).send({
        error: error.message,
        code: 'JWT_INVALID',
        statusCode: 401,
      });
    }
    throw error;
  });
}

async function buildTestApp() {
  const { privateKey, publicKey } = await generateEdDSAKeyPair(true);
  const privateKeyPem = await exportPKCS8(privateKey);
  const publicKeyPem = await exportSPKI(publicKey);

  const app = Fastify({ logger: false });

  await app.register(jwtPlugin, {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    issuer: 'https://auth.test.example.com',
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86400,
  });

  await registerTestErrorHandler(app);

  app.get('/protected', { preHandler: app.requireJwt }, async (request) => ({
    sub: request.jwtPayload?.sub,
    email: request.jwtPayload?.email,
  }));

  return { app, privateKeyPem, publicKeyPem };
}

describe('requireJwt middleware', () => {
  it('allows valid token and sets jwtPayload', async () => {
    const { app, privateKeyPem } = await buildTestApp();

    const token = await signAccessToken(
      {
        sub: 'user-1',
        email: 'user@example.com',
        email_verified: true,
        clientId: 'client-1',
      },
      await importPrivateKey(privateKeyPem),
      'https://auth.test.example.com',
      900
    );

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(response.statusCode).toBe(200);
    const json = response.json();
    expect(json).toEqual({
      sub: 'user-1',
      email: 'user@example.com',
    });

    await app.close();
  });

  it('returns 401 for expired token', async () => {
    const { app, privateKeyPem } = await buildTestApp();

    const token = await signAccessToken(
      {
        sub: 'user-1',
        email: 'user@example.com',
        email_verified: true,
        clientId: 'client-1',
      },
      await importPrivateKey(privateKeyPem),
      'https://auth.test.example.com',
      1
    );

    await new Promise((resolve) => setTimeout(resolve, 1100));

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(response.statusCode).toBe(401);
    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      code: 'JWT_EXPIRED',
      error: expect.any(String),
    });

    await app.close();
  }, 10000);

  it('returns 401 for invalid signature', async () => {
    const { app } = await buildTestApp();
    const { privateKey: otherPrivateKey } = await generateEdDSAKeyPair();

    const token = await signAccessToken(
      {
        sub: 'user-1',
        email: 'user@example.com',
        email_verified: true,
        clientId: 'client-1',
      },
      otherPrivateKey,
      'https://auth.test.example.com',
      900
    );

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    expect(response.statusCode).toBe(401);
    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      code: 'JWT_INVALID',
      error: expect.any(String),
    });

    await app.close();
  });

  it('returns 401 for missing token', async () => {
    const { app } = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
    });

    expect(response.statusCode).toBe(401);
    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      code: 'JWT_INVALID',
      error: 'Missing or malformed Authorization header',
    });

    await app.close();
  });

  it('returns 401 for malformed Authorization header', async () => {
    const { app } = await buildTestApp();

    const response = await app.inject({
      method: 'GET',
      url: '/protected',
      headers: {
        authorization: 'InvalidFormat',
      },
    });

    expect(response.statusCode).toBe(401);
    const json = response.json();
    expect(json).toMatchObject({
      statusCode: 401,
      code: 'JWT_INVALID',
      error: 'Missing or malformed Authorization header',
    });

    await app.close();
  });
});
