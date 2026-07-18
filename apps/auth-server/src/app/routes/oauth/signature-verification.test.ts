/**
 * Real-crypto signature-rejection tests for the token-consuming endpoints
 * (#212 follow-up — closes a genuine coverage gap).
 *
 * The existing introspect/userinfo unit tests STUB `jwtUtils.verifyAccessToken`,
 * so they never exercise actual EdDSA signature verification — a token with a
 * forged/foreign signature would be accepted if the route's wiring were wrong
 * and those tests could not catch it. This suite builds the endpoints with the
 * REAL `jwtPlugin` (keyed by a fresh Ed25519 pair, the same plugin production
 * uses) and feeds them a token signed by a DIFFERENT key, asserting:
 *
 *   - `/oauth/introspect` returns `active: false` for a bad-signature token
 *     (RFC 7662 — an untrusted token is reported inactive, never errored).
 *   - `/oauth/userinfo` rejects a bad-signature bearer token with 401 /
 *     JWT-invalid (the `requireJwt` preHandler runs the real verification).
 *
 * Crypto stays inside the jwt plugin (security boundary). The repositories are
 * lightweight stubs — only the signature path is under test here, not the DB —
 * so this runs in the standard (Docker-free) unit suite.
 */
import { generateKeyPairSync } from 'node:crypto';

import formbody from '@fastify/formbody';
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../helpers/timing', () => ({
  ensureMinimumResponseTime: vi.fn().mockResolvedValue(undefined),
}));

vi.mock('../../../config/env', () => ({
  env: {
    INTROSPECT_RATE_LIMIT: 60,
    INTROSPECT_RATE_WINDOW: 60,
    USERINFO_RATE_LIMIT: 60,
    USERINFO_RATE_WINDOW: 60,
    DEFAULT_REALM_NAME: 'master',
  },
}));

import errorHandler from '../../plugins/error-handler';
import introspectRoute from './introspect';
import userinfoRoute from './userinfo';

const ISSUER = 'https://auth.test.example.com';
const CLIENT_ID = 'sig-test-client';
const USER_ID = '019dbc24-7a2d-724d-bf26-1923f21f2234';

/** Generate a fresh extractable Ed25519 key pair as PEM strings. */
function generateEd25519Pem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

const CONFIDENTIAL_CLIENT = {
  id: 'client-row-sig-1',
  clientId: CLIENT_ID,
  clientSecretHash: 'argon2id$hash',
  enabled: true,
  audience: null as string[] | null,
};

/**
 * Build a Fastify app with the REAL jwt plugin (fresh EdDSA pair) plus the
 * introspect + userinfo routes and the global error handler. Repositories are
 * stubbed; only the signature path matters here.
 */
async function buildApp(): Promise<FastifyInstance> {
  const { privateKeyPem, publicKeyPem } = generateEd25519Pem();

  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  // The introspect route consumes application/x-www-form-urlencoded bodies, the
  // same parser production wires up in app.ts.
  await app.register(formbody);

  await app.register(jwtPlugin, {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    issuer: ISSUER,
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86_400,
  });

  // Minimal repository + redis stubs the two routes touch.
  app.decorate('repositories', {
    realms: {
      findByName: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
      create: vi.fn().mockResolvedValue({ id: 'realm-1', name: 'master', enabled: true }),
    },
    oauthClients: {
      findByClientId: vi.fn().mockResolvedValue(CONFIDENTIAL_CLIENT),
    },
    users: {
      findById: vi.fn().mockResolvedValue({
        id: USER_ID,
        email: 'user@example.com',
        emailVerified: true,
      }),
    },
    auditLogs: { create: vi.fn().mockResolvedValue(undefined) },
    // #229: userinfo resolves email claims from verified attributes.
    userAttributes: {
      findVerifiedByUserIdAndKey: vi.fn().mockResolvedValue([
        {
          id: 'attr-1',
          userId: USER_ID,
          source: 'self_reported',
          attrKey: 'email',
          attrValue: 'user@example.com',
          verified: true,
          expiresAt: null,
          createdAt: 1,
          updatedAt: 1,
        },
      ]),
    },
  } as unknown as FastifyInstance['repositories']);

  app.decorate('passwordHasher', {
    verifyPassword: vi.fn().mockResolvedValue(true),
  } as unknown as FastifyInstance['passwordHasher']);

  // introspect consults the revocation denylist; nothing is revoked here.
  app.decorate('redis', {
    exists: vi.fn().mockResolvedValue(0),
    setex: vi.fn().mockResolvedValue('OK'),
  } as unknown as FastifyInstance['redis']);

  await app.register(errorHandler);
  await app.register(async (instance) => {
    await introspectRoute(instance.withTypeProvider<ZodTypeProvider>());
    await userinfoRoute(instance.withTypeProvider<ZodTypeProvider>());
  });

  await app.ready();
  return app;
}

describe('real EdDSA signature verification — token-consuming endpoints', () => {
  it('introspect returns active: false for a token signed by a foreign key', async () => {
    const app = await buildApp();
    const otherApp = await buildApp(); // independent signing key
    try {
      // Minted on the OTHER server (different key); THIS server must not trust it.
      const foreignToken = await otherApp.jwtUtils.signAccessToken({
        sub: USER_ID,
        clientId: CLIENT_ID,
        email: 'user@example.com',
        email_verified: true,
        scope: 'openid',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/introspect',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({
          token: foreignToken,
          client_id: CLIENT_ID,
          client_secret: 'secret',
        }).toString(),
      });

      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ active: false });
    } finally {
      await app.close();
      await otherApp.close();
    }
  });

  it('introspect returns active: false for a token with a structurally mutated signature', async () => {
    const app = await buildApp();
    try {
      // A token THIS server signed, then tampered: flip the signature segment.
      const valid = await app.jwtUtils.signAccessToken({
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid',
      });
      const [h, p] = valid.split('.');
      const tampered = `${h}.${p}.${'A'.repeat(86)}`;

      const res = await app.inject({
        method: 'POST',
        url: '/introspect',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({
          token: tampered,
          client_id: CLIENT_ID,
          client_secret: 'secret',
        }).toString(),
      });

      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ active: false });
    } finally {
      await app.close();
    }
  });

  it('introspect returns active: true for a genuinely signed same-client token (control)', async () => {
    const app = await buildApp();
    try {
      const token = await app.jwtUtils.signAccessToken({
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid',
      });

      const res = await app.inject({
        method: 'POST',
        url: '/introspect',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({
          token,
          client_id: CLIENT_ID,
          client_secret: 'secret',
        }).toString(),
      });

      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ active: true, client_id: CLIENT_ID });
    } finally {
      await app.close();
    }
  });

  it('userinfo rejects a bearer token signed by a foreign key (401 / JWT invalid)', async () => {
    const app = await buildApp();
    const otherApp = await buildApp();
    try {
      const foreignToken = await otherApp.jwtUtils.signAccessToken({
        sub: USER_ID,
        clientId: CLIENT_ID,
        email: 'user@example.com',
        email_verified: true,
        scope: 'openid email',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/userinfo',
        headers: { authorization: `Bearer ${foreignToken}` },
      });

      expect(res.statusCode).toBe(401);
      // The user lookup must never run when the signature is untrusted.
      const usersRepo = app.repositories.users as unknown as { findById: ReturnType<typeof vi.fn> };
      expect(usersRepo.findById).not.toHaveBeenCalled();
    } finally {
      await app.close();
      await otherApp.close();
    }
  });

  it('userinfo rejects a bearer token with a structurally mutated signature (401)', async () => {
    const app = await buildApp();
    try {
      const valid = await app.jwtUtils.signAccessToken({
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid email',
      });
      const [h, p] = valid.split('.');
      const tampered = `${h}.${p}.${'A'.repeat(86)}`;

      const res = await app.inject({
        method: 'GET',
        url: '/userinfo',
        headers: { authorization: `Bearer ${tampered}` },
      });

      expect(res.statusCode).toBe(401);
    } finally {
      await app.close();
    }
  });

  it('userinfo accepts a genuinely signed bearer token (control)', async () => {
    const app = await buildApp();
    try {
      const token = await app.jwtUtils.signAccessToken({
        sub: USER_ID,
        clientId: CLIENT_ID,
        email: 'user@example.com',
        email_verified: true,
        scope: 'openid email',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/userinfo',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ sub: USER_ID, email: 'user@example.com' });
    } finally {
      await app.close();
    }
  });
});
