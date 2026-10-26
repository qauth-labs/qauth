/**
 * Real-crypto signature-rejection tests for the token-consuming endpoints
 * (#212 follow-up — closes a genuine coverage gap).
 *
 * The existing introspect/userinfo unit tests STUB `jwtUtils.verifyAccessToken`,
 * so they never exercise actual EdDSA signature verification — a token with a
 * forged/foreign signature would be accepted if the route's wiring were wrong
 * and those tests could not catch it. This suite builds the endpoints with the
 * REAL `jwtPlugin` over the real in-process signer, the same plugin and signer
 * production uses (#491: every token is signed and verified per realm, with
 * the realm's own keys, which the signer holds in memory here), and feeds them
 * a token signed by a DIFFERENT key, asserting:
 *
 *   - `/oauth/introspect` returns `active: false` for a bad-signature token
 *     (RFC 7662 — an untrusted token is reported inactive, never errored).
 *   - `/oauth/userinfo` rejects a bad-signature bearer token with 401 /
 *     JWT-invalid (the `requireJwt` preHandler runs the real verification).
 *
 * The foreign tokens are another server's, whose realm has the same id and
 * issuer but keys of its own; one signed by hand with a foreign key and no
 * `kid` (as a release before #491 signed one), which reaches the signature
 * check itself; and those another realm of the same server mints (ADR-019
 * Decision 1: a token of another realm verifies with none of the request
 * realm's keys).
 *
 * Crypto stays inside the jwt plugin and the signer (security boundary); the
 * one token signed by hand is signed with `node:crypto`. The repositories are
 * lightweight stubs — only the signature path is under test here, not the DB —
 * so this runs in the standard (Docker-free) unit suite.
 */
import { generateKeyPairSync, sign } from 'node:crypto';

import formbody from '@fastify/formbody';
import { jwtPlugin, type TokenRealm } from '@qauth-labs/fastify-plugin-jwt';
import { createTestSigner } from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../../helpers/user-events', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../helpers/user-events')>();
  const { checkedEmitUserEvent } = await import('../../../testing/user-events');
  return { ...actual, emitUserEvent: vi.fn(checkedEmitUserEvent(actual.userEventFor)) };
});

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

import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import { tokenRealm } from '../../helpers/realm-url';
import errorHandler from '../../plugins/error-handler';
import introspectRoute from './introspect';
import userinfoRoute from './userinfo';

const ISSUER = 'https://auth.test.example.com';
/** The issuer of the server's second realm, which no request here belongs to. */
const OTHER_ISSUER = 'https://other.test.example.com';
const CLIENT_ID = 'sig-test-client';
const USER_ID = '019dbc24-7a2d-724d-bf26-1923f21f2234';

const CONFIDENTIAL_CLIENT = {
  id: 'client-row-sig-1',
  clientId: CLIENT_ID,
  clientSecretHash: 'argon2id$hash',
  enabled: true,
  audience: null as string[] | null,
};

/** A server and its realms. */
interface TestServer {
  readonly app: FastifyInstance;
  /** The realm every request belongs to, as the JWT plugin takes it. */
  readonly realm: TokenRealm;
  /** A second realm of the same server, with keys and an issuer of its own. */
  readonly otherRealm: TokenRealm;
}

/**
 * Build a Fastify app with the REAL jwt plugin over the real in-memory signer
 * (fresh keys for each realm) plus the introspect + userinfo routes and the
 * global error handler. Repositories are stubbed; only the signature path
 * matters here.
 *
 * @param realmId - the request realm's id; a new UUID when absent. Another
 *   server's realm may share it, so only the keys tell their tokens apart.
 */
async function buildApp(realmId?: string): Promise<TestServer> {
  const signer = createTestSigner();
  const realm = testRealm({
    id: await signer.addRealm({
      issuer: ISSUER,
      ...(realmId === undefined ? {} : { id: realmId }),
    }),
    issuer: ISSUER,
  });
  const otherRealm = {
    id: await signer.addRealm({ issuer: OTHER_ISSUER }),
    issuer: OTHER_ISSUER,
  };

  const app = Fastify({ logger: false });
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  // The introspect route consumes application/x-www-form-urlencoded bodies, the
  // same parser production wires up in app.ts.
  await app.register(formbody);

  await app.register(jwtPlugin, {
    signer: signer.signer,
    // As app.ts wires it: a request's tokens are its realm's.
    requestRealm: () => tokenRealm(realm),
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86_400,
  });

  // Minimal repository + redis stubs the two routes touch.
  app.decorate('repositories', {
    oauthClients: {
      findByClientId: vi.fn().mockResolvedValue(CONFIDENTIAL_CLIENT),
    },
    users: {
      findById: vi.fn().mockResolvedValue({
        id: USER_ID,
        email: 'user@example.com',
        emailVerified: true,
        enabled: true,
      }),
    },
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
  // The realm resolver's decoration (#486): every request carries its host's realm.
  supplyRequestRealm(app, realm);
  await app.register(async (instance) => {
    await introspectRoute(instance.withTypeProvider<ZodTypeProvider>());
    await userinfoRoute(instance.withTypeProvider<ZodTypeProvider>());
  });

  await app.ready();
  return { app, realm: tokenRealm(realm), otherRealm };
}

/**
 * An access token signed by hand with a fresh Ed25519 key no realm holds, and
 * with no `kid` header, as a release before tokens named their key (#491)
 * signed one: the verifier tries each EdDSA key of the realm, so the token
 * reaches the signature check itself. Signed with `node:crypto` only.
 */
function forgeKidlessToken(claims: Record<string, unknown>): string {
  const { privateKey } = generateKeyPairSync('ed25519');
  const now = Math.floor(Date.now() / 1000);
  const encode = (part: Record<string, unknown>) =>
    Buffer.from(JSON.stringify(part)).toString('base64url');
  const signingInput = `${encode({ alg: 'EdDSA', typ: 'at+jwt' })}.${encode({
    iss: ISSUER,
    aud: CLIENT_ID,
    client_id: CLIENT_ID,
    iat: now,
    exp: now + 900,
    jti: 'forged-jti',
    ...claims,
  })}`;
  const signature = sign(null, Buffer.from(signingInput), privateKey);
  return `${signingInput}.${signature.toString('base64url')}`;
}

/** POST `token` to `/introspect` as the confidential client. */
function introspect(app: FastifyInstance, token: string) {
  return app.inject({
    method: 'POST',
    url: '/introspect',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    payload: new URLSearchParams({
      token,
      client_id: CLIENT_ID,
      client_secret: 'secret',
    }).toString(),
  });
}

describe('real EdDSA signature verification — token-consuming endpoints', () => {
  it('introspect returns active: false for a token signed by a foreign key', async () => {
    const { app, realm } = await buildApp();
    // Independent signing keys for a realm with the same id and issuer.
    const other = await buildApp(realm.id);
    try {
      // Minted on the OTHER server (different key); THIS server must not trust it.
      const foreignToken = await other.app.jwtUtils.signAccessToken(other.realm, {
        sub: USER_ID,
        clientId: CLIENT_ID,
        email: 'user@example.com',
        email_verified: true,
        scope: 'openid',
      });
      // And one with no `kid`, which the realm's EdDSA key must refuse on its
      // signature.
      const forged = forgeKidlessToken({ sub: USER_ID, scope: 'openid' });
      // Each is refused on the key: the first names one the realm does not
      // publish, the second fails the signature check of the realm's key.
      await expect(app.jwtUtils.verifyAccessToken(realm, foreignToken)).rejects.toThrow(
        /no key of this realm verifies it/
      );
      await expect(app.jwtUtils.verifyAccessToken(realm, forged)).rejects.toThrow(/signature/i);

      for (const token of [foreignToken, forged]) {
        const res = await introspect(app, token);
        expect(res.statusCode).toBe(200);
        expect(res.json()).toEqual({ active: false });
      }
    } finally {
      await app.close();
      await other.app.close();
    }
  });

  it('introspect returns active: false for a token another realm of the same server minted (#491)', async () => {
    const { app, realm, otherRealm } = await buildApp();
    try {
      // Genuine in its own realm, and naming its own realm's issuer: the
      // request realm's keys must not verify it.
      const token = await app.jwtUtils.signAccessToken(otherRealm, {
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid',
      });
      await expect(app.jwtUtils.verifyAccessToken(otherRealm, token)).resolves.toMatchObject({
        iss: OTHER_ISSUER,
      });
      await expect(app.jwtUtils.verifyAccessToken(realm, token)).rejects.toThrow(
        /no key of this realm verifies it/
      );

      const res = await introspect(app, token);
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ active: false });
    } finally {
      await app.close();
    }
  });

  it('introspect returns active: false for a token with a structurally mutated signature', async () => {
    const { app, realm } = await buildApp();
    try {
      // A token THIS server signed, then tampered: flip the signature segment.
      const valid = await app.jwtUtils.signAccessToken(realm, {
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid',
      });
      const [h, p] = valid.split('.');
      const tampered = `${h}.${p}.${'A'.repeat(86)}`;

      const res = await introspect(app, tampered);

      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({ active: false });
    } finally {
      await app.close();
    }
  });

  it('introspect returns active: true for a genuinely signed same-client token (control)', async () => {
    const { app, realm } = await buildApp();
    try {
      const token = await app.jwtUtils.signAccessToken(realm, {
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid',
      });

      const res = await introspect(app, token);

      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ active: true, client_id: CLIENT_ID, iss: ISSUER });
    } finally {
      await app.close();
    }
  });

  it('userinfo rejects a bearer token signed by a foreign key (401 / JWT invalid)', async () => {
    const { app, realm } = await buildApp();
    const other = await buildApp(realm.id);
    try {
      const foreignToken = await other.app.jwtUtils.signAccessToken(other.realm, {
        sub: USER_ID,
        clientId: CLIENT_ID,
        email: 'user@example.com',
        email_verified: true,
        scope: 'openid email',
      });
      const forged = forgeKidlessToken({ sub: USER_ID, scope: 'openid email' });

      for (const token of [foreignToken, forged]) {
        const res = await app.inject({
          method: 'GET',
          url: '/userinfo',
          headers: { authorization: `Bearer ${token}` },
        });

        expect(res.statusCode).toBe(401);
        expect(res.json()).toEqual({
          error: 'invalid_token',
          error_description: expect.any(String),
        });
      }
      // The user lookup must never run when the signature is untrusted.
      const usersRepo = app.repositories.users as unknown as { findById: ReturnType<typeof vi.fn> };
      expect(usersRepo.findById).not.toHaveBeenCalled();
    } finally {
      await app.close();
      await other.app.close();
    }
  });

  it('userinfo rejects a bearer token another realm of the same server minted (401, #491)', async () => {
    const { app, otherRealm } = await buildApp();
    try {
      const token = await app.jwtUtils.signAccessToken(otherRealm, {
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

      expect(res.statusCode).toBe(401);
      expect(res.json()).toEqual({ error: 'invalid_token', error_description: expect.any(String) });
      const usersRepo = app.repositories.users as unknown as { findById: ReturnType<typeof vi.fn> };
      expect(usersRepo.findById).not.toHaveBeenCalled();
    } finally {
      await app.close();
    }
  });

  it('userinfo rejects a bearer token with a structurally mutated signature (401)', async () => {
    const { app, realm } = await buildApp();
    try {
      const valid = await app.jwtUtils.signAccessToken(realm, {
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
      expect(res.json()).toMatchObject({ error: 'invalid_token' });
    } finally {
      await app.close();
    }
  });

  it('userinfo accepts a genuinely signed bearer token (control)', async () => {
    const { app, realm } = await buildApp();
    try {
      const token = await app.jwtUtils.signAccessToken(realm, {
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

  // NOIEWQ7H: a genuine, live token minted for ANOTHER resource server passes
  // `requireJwt` (signature, issuer, expiry, revocation) — the audience rule in
  // the route is what refuses it.
  it('userinfo refuses a genuinely signed token whose audience is another resource server (401)', async () => {
    const { app, realm } = await buildApp();
    try {
      const token = await app.jwtUtils.signAccessToken(realm, {
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid email',
        aud: 'http://localhost:8088',
      });

      const res = await app.inject({
        method: 'GET',
        url: '/userinfo',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(res.statusCode).toBe(401);
      expect(res.headers['www-authenticate']).toContain('error="invalid_token"');
      expect(res.json()).toMatchObject({ error: 'invalid_token' });
      expect(res.json()).not.toHaveProperty('email');
    } finally {
      await app.close();
    }
  });

  it('userinfo accepts a genuinely signed token whose audience lists the userinfo endpoint', async () => {
    const { app, realm } = await buildApp();
    try {
      const token = await app.jwtUtils.signAccessToken(realm, {
        sub: USER_ID,
        clientId: CLIENT_ID,
        scope: 'openid email',
        aud: ['http://localhost:8088', `${ISSUER}/oauth/userinfo`],
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
