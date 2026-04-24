import { generateEdDSAKeyPair, importPrivateKey, signAccessToken } from '@qauth-labs/server-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { exportPKCS8, exportSPKI, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { jwtPlugin } from './fastify-plugin-jwt';

/**
 * Sign an already-expired token (avoids flaky setTimeout-based tests).
 * Uses past exp timestamp so verification fails immediately with JWTExpiredError.
 */
async function signExpiredToken(
  privateKeyPem: string,
  payload: { sub: string; email: string; email_verified: boolean; clientId: string }
): Promise<string> {
  const key = await importPrivateKey(privateKeyPem);
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({
    sub: payload.sub,
    email: payload.email,
    email_verified: payload.email_verified,
    client_id: payload.clientId,
  })
    .setProtectedHeader({ alg: 'EdDSA' })
    .setIssuedAt(now - 3600)
    .setExpirationTime(now - 60)
    .setIssuer('https://auth.test.example.com')
    .sign(key);
}

/**
 * Minimal error handler for tests - maps JWT errors to 401.
 * Kept local (not imported from auth-server) to avoid pulling in auth-server
 * dependencies into the fastify-plugin-jwt library.
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
    try {
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
    } finally {
      await app.close();
    }
  });

  it('returns 401 for expired token', async () => {
    const { app, privateKeyPem } = await buildTestApp();
    try {
      const token = await signExpiredToken(privateKeyPem, {
        sub: 'user-1',
        email: 'user@example.com',
        email_verified: true,
        clientId: 'client-1',
      });

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
    } finally {
      await app.close();
    }
  });

  it('returns 401 for invalid signature', async () => {
    const { app } = await buildTestApp();
    try {
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
    } finally {
      await app.close();
    }
  });

  it('returns 401 for missing token', async () => {
    const { app } = await buildTestApp();
    try {
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
    } finally {
      await app.close();
    }
  });

  it('exposes getIssuer() returning the configured issuer', async () => {
    const { app } = await buildTestApp();
    try {
      expect(app.jwtUtils.getIssuer()).toBe('https://auth.test.example.com');
    } finally {
      await app.close();
    }
  });

  it('exposes getJwks() returning a JWKS that verifies issued tokens', async () => {
    const { app, privateKeyPem } = await buildTestApp();
    try {
      const jwks = await app.jwtUtils.getJwks();

      expect(jwks.keys).toHaveLength(1);
      const [jwk] = jwks.keys;
      expect(jwk.alg).toBe('EdDSA');
      expect(jwk.use).toBe('sig');
      expect(jwk).not.toHaveProperty('d');

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

      const key = await importJWK(jwk, 'EdDSA');
      const { payload } = await jwtVerify(token, key, { algorithms: ['EdDSA'] });
      expect(payload.sub).toBe('user-1');
    } finally {
      await app.close();
    }
  });

  it('returns 401 for malformed Authorization header', async () => {
    const { app } = await buildTestApp();
    try {
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
    } finally {
      await app.close();
    }
  });
});
