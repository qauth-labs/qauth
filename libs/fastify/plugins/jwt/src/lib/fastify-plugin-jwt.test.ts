import { generateKeyPairSync, KeyObject } from 'node:crypto';

import {
  createTestSigner,
  type TestSigner,
} from '@qauth-labs/fastify-plugin-signer/src/testing/memory-signer';
import {
  JWTExpiredError,
  JWTInvalidError,
  MissingAccessTokenError,
  TemporarilyUnavailableError,
} from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import Fastify from 'fastify';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  importPKCS8,
  type JSONWebKeySet,
  jwtVerify,
  SignJWT,
} from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { JwtPluginOptions, TokenRealm } from '../types';
import { jwtPlugin } from './fastify-plugin-jwt';

/** Operator-enabled algorithm set (SIGNING_ALGORITHM_MODE=ed25519+ml-dsa-65). */
const PQC_ENABLED = ['EdDSA', 'ML-DSA-65'] as const;

const ISSUER_A = 'https://a.test.example.com';
const ISSUER_B = 'https://b.test.example.com';

/** An Ed25519 private key, PKCS#8 PEM, as `JWT_PRIVATE_KEY` holds one. */
function ed25519Pem(): string {
  return generateKeyPairSync('ed25519')
    .privateKey.export({ type: 'pkcs8', format: 'pem' })
    .toString();
}

/**
 * Minimal error handler for tests - maps JWT errors to 401.
 * Kept local (not imported from auth-server) to avoid pulling in auth-server
 * dependencies into the fastify-plugin-jwt library.
 */
async function registerTestErrorHandler(app: FastifyInstance) {
  app.setErrorHandler((error, _request, reply) => {
    if (
      error instanceof JWTExpiredError ||
      error instanceof JWTInvalidError ||
      error instanceof MissingAccessTokenError
    ) {
      return reply.code(401).send({
        error: error.message,
        code: error.code,
        statusCode: 401,
      });
    }
    throw error;
  });
}

/** Two realms with keys of their own; realm A's EdDSA key is `realmAKey`. */
interface TestRealms {
  readonly signer: TestSigner;
  readonly a: TokenRealm;
  readonly b: TokenRealm;
  /** The PEM of realm A's EdDSA `token_signing` key, imported as a variable would be. */
  readonly realmAKey: string;
  /** Its `kid`, which a token without a `kid` may be verified with; none for a hybrid realm. */
  readonly realmAKeyKid?: string;
}

async function createRealms(
  options: { hybridSigning?: boolean; rs256?: boolean; refreshIntervalMs?: number } = {}
): Promise<TestRealms> {
  const signer = createTestSigner({
    hybridSigning: options.hybridSigning === true,
    ...(options.refreshIntervalMs === undefined
      ? {}
      : { refreshIntervalMs: options.refreshIntervalMs }),
  });
  // A hybrid realm's EdDSA key is half a pair, which a variable cannot import
  // alone; such a realm gets generated keys.
  const realmAKey = ed25519Pem();
  const a = {
    id: await signer.addRealm({
      issuer: ISSUER_A,
      rs256: options.rs256 === true,
      ...(options.hybridSigning === true ? {} : { ed25519PrivateKey: realmAKey }),
    }),
    issuer: ISSUER_A,
  };
  const b = { id: await signer.addRealm({ issuer: ISSUER_B }), issuer: ISSUER_B };
  const realmAKeyKid =
    options.hybridSigning === true
      ? undefined
      : (await signer.signer.getVerificationKeys('local', a.id, 'token_signing')).find(
          (key) => key.algorithm === 'EdDSA'
        )?.kid;
  return { signer, a, b, realmAKey, ...(realmAKeyKid === undefined ? {} : { realmAKeyKid }) };
}

/**
 * A server whose requests belong to realm A, or to realm B when they send
 * `x-test-realm: b`.
 */
async function buildTestApp(
  realms: TestRealms,
  options: Partial<JwtPluginOptions> = {}
): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(jwtPlugin, {
    signer: realms.signer.signer,
    requestRealm: (request) => (request.headers['x-test-realm'] === 'b' ? realms.b : realms.a),
    accessTokenLifespan: 900,
    refreshTokenLifespan: 86400,
    // Realm A's key came from a key variable, as before #491.
    ...(realms.realmAKeyKid === undefined ? {} : { kidlessKeyIds: [realms.realmAKeyKid] }),
    ...options,
  });
  await registerTestErrorHandler(app);
  app.get('/protected', { preHandler: app.requireJwt }, async (request) => ({
    sub: request.jwtPayload?.sub,
    email: request.jwtPayload?.email,
    iss: request.jwtPayload?.iss,
    cnf: request.jwtPayload?.cnf ?? null,
  }));
  return app;
}

/** The `kid` of the realm's active key of `algorithm`, as the signer lists it. */
async function activeKid(
  realms: TestRealms,
  realm: TokenRealm,
  algorithm: string
): Promise<string> {
  const keys = await realms.signer.signer.getVerificationKeys('local', realm.id, 'token_signing');
  const key = keys.find((candidate) => candidate.algorithm === algorithm);
  if (key === undefined) throw new Error(`no ${algorithm} key`);
  return key.kid;
}

/** A token signed with `pem` the way a release before the key store signed one: no `kid`. */
async function signWithPem(
  pem: string,
  claims: {
    iss?: string;
    typ?: string;
    kid?: string;
    jti?: string;
    exp?: number;
    aud?: string;
  } = {}
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const jwt = new SignJWT({ sub: 'user-1', client_id: 'client-1', jti: claims.jti ?? 'jti-1' })
    .setProtectedHeader({
      alg: 'EdDSA',
      ...(claims.typ === undefined ? {} : { typ: claims.typ }),
      ...(claims.kid === undefined ? {} : { kid: claims.kid }),
    })
    .setIssuedAt(now - 60)
    .setExpirationTime(claims.exp ?? now + 900);
  if (claims.iss !== undefined) jwt.setIssuer(claims.iss);
  if (claims.aud !== undefined) jwt.setAudience(claims.aud);
  return jwt.sign(await importPKCS8(pem, 'EdDSA'));
}

function header(token: string): Record<string, unknown> {
  return { ...decodeProtectedHeader(token) };
}

function payload(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf-8')) as Record<
    string,
    unknown
  >;
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('requireJwt middleware', () => {
  it('allows a token of the request realm and sets jwtPayload', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const token = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        email: 'user@example.com',
        email_verified: true,
        clientId: 'client-1',
      });

      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(response.statusCode).toBe(200);
      expect(response.json()).toEqual({
        sub: 'user-1',
        email: 'user@example.com',
        iss: ISSUER_A,
        cnf: null,
      });
    } finally {
      await app.close();
    }
  });

  it('refuses a token of another realm outright (ADR-019 Decision 1)', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const tokenOfB = await app.jwtUtils.signAccessToken(realms.b, {
        sub: 'user-1',
        clientId: 'client-1',
      });

      const atA = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${tokenOfB}` },
      });
      expect(atA.statusCode).toBe(401);
      expect(atA.json()).toMatchObject({ code: 'INVALID_ACCESS_TOKEN' });

      const atB = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${tokenOfB}`, 'x-test-realm': 'b' },
      });
      expect(atB.statusCode).toBe(200);
      expect(atB.json()).toMatchObject({ iss: ISSUER_B });
    } finally {
      await app.close();
    }
  });

  it('returns 401 for an expired token', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const token = await signWithPem(realms.realmAKey, {
        iss: ISSUER_A,
        exp: Math.floor(Date.now() / 1000) - 60,
      });

      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        statusCode: 401,
        code: 'ACCESS_TOKEN_EXPIRED',
        error: expect.any(String),
      });
    } finally {
      await app.close();
    }
  });

  it('returns 401 for a signature by another key under the realm key id', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const token = await signWithPem(ed25519Pem(), {
        iss: ISSUER_A,
        typ: 'at+jwt',
        kid: await activeKid(realms, realms.a, 'EdDSA'),
      });

      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${token}` },
      });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        statusCode: 401,
        code: 'INVALID_ACCESS_TOKEN',
        error: expect.any(String),
      });
    } finally {
      await app.close();
    }
  });

  it('returns 401 for missing token', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const response = await app.inject({ method: 'GET', url: '/protected' });

      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        statusCode: 401,
        // No credential is not a refused token (RFC 6750 §3.1).
        code: 'UNAUTHORIZED',
        error: 'Missing or malformed Authorization header',
      });
    } finally {
      await app.close();
    }
  });

  it('returns 401 for malformed Authorization header', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      for (const authorization of ['Basic abc', 'Bearer', 'Bearer not-a-jwt']) {
        const response = await app.inject({
          method: 'GET',
          url: '/protected',
          headers: { authorization },
        });
        expect(response.statusCode).toBe(401);
      }
    } finally {
      await app.close();
    }
  });
});

describe('signing through the signer (#491)', () => {
  it('signs access tokens with the realm issuer and the kid of its active EdDSA key', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const tokenA = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      const tokenB = await app.jwtUtils.signAccessToken(realms.b, {
        sub: 'user-1',
        clientId: 'client-1',
      });

      expect(header(tokenA)).toEqual({
        alg: 'EdDSA',
        kid: await activeKid(realms, realms.a, 'EdDSA'),
        typ: 'at+jwt',
      });
      expect(header(tokenB)['kid']).toBe(await activeKid(realms, realms.b, 'EdDSA'));
      expect(header(tokenA)['kid']).not.toBe(header(tokenB)['kid']);
      expect(payload(tokenA)).toMatchObject({
        iss: ISSUER_A,
        sub: 'user-1',
        client_id: 'client-1',
        aud: 'client-1',
        token_use: 'access',
      });
      expect(payload(tokenB)['iss']).toBe(ISSUER_B);
    } finally {
      await app.close();
    }
  });

  it('gives a token the configured lifespan, or the shorter override', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const token = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      const clamped = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
        expiresInOverride: 60,
      });

      const claims = payload(token);
      expect((claims['exp'] as number) - (claims['iat'] as number)).toBe(900);
      const clampedClaims = payload(clamped);
      expect((clampedClaims['exp'] as number) - (clampedClaims['iat'] as number)).toBe(60);
    } finally {
      await app.close();
    }
  });

  it("serves each realm's JWKS: a realm's tokens verify with its JWKS and not with another's", async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const jwksA = await app.jwtUtils.getJwks(realms.a);
      const jwksB = await app.jwtUtils.getJwks(realms.b);
      expect(jwksA.keys.map((key) => key.kid)).toEqual([
        await activeKid(realms, realms.a, 'EdDSA'),
      ]);
      for (const key of [...jwksA.keys, ...jwksB.keys]) {
        expect(key).not.toHaveProperty('d');
        expect(key).toMatchObject({ alg: 'EdDSA', use: 'sig' });
      }

      const token = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      await expect(
        jwtVerify(token, createLocalJWKSet(jwksA as JSONWebKeySet), { issuer: ISSUER_A })
      ).resolves.toBeDefined();
      await expect(
        jwtVerify(token, createLocalJWKSet(jwksB as JSONWebKeySet))
      ).rejects.toMatchObject({ code: 'ERR_JWKS_NO_MATCHING_KEY' });
    } finally {
      await app.close();
    }
  });

  it('signs ID tokens with EdDSA, or with RS256 when the realm has an RS256 key, each with its kid', async () => {
    const plain = await createRealms();
    const withRs256 = await createRealms({ rs256: true });
    const plainApp = await buildTestApp(plain);
    const rsaApp = await buildTestApp(withRs256);
    try {
      const edIdToken = await plainApp.jwtUtils.signIdToken(plain.a, {
        sub: 'user-1',
        audience: 'client-1',
      });
      expect(header(edIdToken)).toEqual({
        alg: 'EdDSA',
        kid: await activeKid(plain, plain.a, 'EdDSA'),
        typ: 'JWT',
      });
      expect(await plainApp.jwtUtils.getIdTokenSigningAlgValuesSupported(plain.a)).toEqual([
        'EdDSA',
      ]);

      const rsaIdToken = await rsaApp.jwtUtils.signIdToken(withRs256.a, {
        sub: 'user-1',
        audience: 'client-1',
        nonce: 'n-1',
      });
      expect(header(rsaIdToken)).toEqual({
        alg: 'RS256',
        kid: await activeKid(withRs256, withRs256.a, 'RS256'),
        typ: 'JWT',
      });
      expect(payload(rsaIdToken)).toMatchObject({
        iss: ISSUER_A,
        aud: 'client-1',
        nonce: 'n-1',
        token_use: 'id',
      });
      expect(await rsaApp.jwtUtils.getIdTokenSigningAlgValuesSupported(withRs256.a)).toEqual([
        'RS256',
        'EdDSA',
      ]);
      // The other realm has no RS256 key: EdDSA ID tokens there.
      expect(await rsaApp.jwtUtils.getIdTokenSigningAlgValuesSupported(withRs256.b)).toEqual([
        'EdDSA',
      ]);

      const jwks = await rsaApp.jwtUtils.getJwks(withRs256.a);
      await expect(
        jwtVerify(rsaIdToken, createLocalJWKSet(jwks as JSONWebKeySet), {
          issuer: ISSUER_A,
          audience: 'client-1',
        })
      ).resolves.toBeDefined();
    } finally {
      await plainApp.close();
      await rsaApp.close();
    }
  });

  it('signs with no store read once the signer has the keys', async () => {
    const realms = await createRealms({ rs256: true });
    const app = await buildTestApp(realms);
    try {
      await app.jwtUtils.signAccessToken(realms.a, { sub: 'user-1', clientId: 'client-1' });
      await app.jwtUtils.signIdToken(realms.a, { sub: 'user-1', audience: 'client-1' });
      const reads = realms.signer.storeReads.length;

      await app.jwtUtils.signAccessToken(realms.a, { sub: 'user-2', clientId: 'client-1' });
      await app.jwtUtils.signIdToken(realms.a, { sub: 'user-2', audience: 'client-1' });
      expect(realms.signer.storeReads.slice(reads)).toEqual([]);
    } finally {
      await app.close();
    }
  });
});

describe('verifying with the realm keys (#491)', () => {
  it('verifies a token with no kid, signed before tokens named their key, with the imported key only', async () => {
    const realms = await createRealms();
    const importedKid = await activeKid(realms, realms.a, 'EdDSA');
    expect(realms.realmAKeyKid).toBe(importedKid);
    const app = await buildTestApp(realms, { kidlessKeyIds: [importedKid] });
    try {
      const legacy = await signWithPem(realms.realmAKey, { iss: ISSUER_A, aud: 'client-1' });
      expect(header(legacy)).not.toHaveProperty('kid');

      await expect(app.jwtUtils.verifyAccessToken(realms.a, legacy)).resolves.toMatchObject({
        sub: 'user-1',
        iss: ISSUER_A,
      });
      // Not in another realm: its keys did not sign it.
      await expect(
        app.jwtUtils.verifyAccessToken({ ...realms.b, issuer: ISSUER_A }, legacy)
      ).rejects.toThrow(JWTInvalidError);
      // A key no variable imported is never tried for a token without a kid.
      const other = await signWithPem(ed25519Pem(), { iss: ISSUER_A, aud: 'client-1' });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, other)).rejects.toThrow(
        JWTInvalidError
      );
    } finally {
      await app.close();
    }
  });

  it('verifies no token without a kid when no imported key is named, nor with a generated key', async () => {
    const realms = await createRealms();
    const legacy = await signWithPem(realms.realmAKey, { iss: ISSUER_A, aud: 'client-1' });
    // Realm B's key was generated by the store: it never signed a token without a kid.
    const generatedKid = await activeKid(realms, realms.b, 'EdDSA');
    for (const kidlessKeyIds of [[], [generatedKid]]) {
      const app = await buildTestApp(realms, { kidlessKeyIds });
      try {
        await expect(app.jwtUtils.verifyAccessToken(realms.a, legacy)).rejects.toThrow(
          'no key of this realm verifies it'
        );
      } finally {
        await app.close();
      }
    }
  });

  it("refuses a kid the realm does not publish, and one naming the realm's RS256 key", async () => {
    const realms = await createRealms({ rs256: true });
    const app = await buildTestApp(realms);
    try {
      const unknownKid = await signWithPem(realms.realmAKey, {
        iss: ISSUER_A,
        kid: 'no-such-key',
      });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, unknownKid)).rejects.toThrow(
        'no key of this realm verifies it'
      );

      const rsaKid = await signWithPem(realms.realmAKey, {
        iss: ISSUER_A,
        kid: await activeKid(realms, realms.a, 'RS256'),
      });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, rsaKid)).rejects.toThrow(
        JWTInvalidError
      );
    } finally {
      await app.close();
    }
  });

  it.each(['compromised', 'next'] as const)(
    'refuses a token whose kid names a %s key, which the realm does not list for verification',
    async (status) => {
      // The signer reads the store on every call, so the status change shows at once.
      const realms = await createRealms({ refreshIntervalMs: 0 });
      const app = await buildTestApp(realms);
      try {
        const token = await app.jwtUtils.signAccessToken(realms.a, {
          sub: 'user-1',
          clientId: 'client-1',
        });
        await expect(app.jwtUtils.verifyAccessToken(realms.a, token)).resolves.toBeDefined();

        // The key that made the signature, so only its status can refuse it.
        const kid = await activeKid(realms, realms.a, 'EdDSA');
        expect(header(token)['kid']).toBe(kid);
        realms.signer.setKeyStatus(realms.a.id, kid, status);
        await expect(app.jwtUtils.verifyAccessToken(realms.a, token)).rejects.toThrow(
          'no key of this realm verifies it'
        );
      } finally {
        await app.close();
      }
    }
  );

  it("refuses a kid naming the realm's ML-DSA-65 key on an EdDSA token: (kid, alg) finds no key", async () => {
    const realms = await createRealms({ hybridSigning: true });
    const app = await buildTestApp(realms, {
      hybridSigningEnabled: true,
      enabledSignatureAlgorithms: PQC_ENABLED,
    });
    try {
      const mlDsaKid = await activeKid(realms, realms.a, 'ML-DSA-65');
      const token = await signWithPem(ed25519Pem(), { iss: ISSUER_A, kid: mlDsaKid });
      expect(header(token)).toMatchObject({ alg: 'EdDSA', kid: mlDsaKid });
      // Refused at key selection, before any signature is checked.
      await expect(app.jwtUtils.verifyAccessToken(realms.a, token)).rejects.toThrow(
        'no key of this realm verifies it'
      );
    } finally {
      await app.close();
    }
  });

  it('reports an expired ID token of the realm as invalid, never as an expired access token (logout)', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const now = Math.floor(Date.now() / 1000);
      const expired = (typ: 'at+jwt' | 'JWT') =>
        realms.signer.signer.signJws('local', {
          realmId: realms.a.id,
          purpose: 'token_signing',
          typ,
          claims: {
            sub: 'user-1',
            client_id: 'client-1',
            aud: 'client-1',
            iat: now - 3600,
            exp: now - 1800,
          },
        });
      await expect(
        app.jwtUtils.verifyAccessToken(realms.a, await expired('at+jwt'))
      ).rejects.toBeInstanceOf(JWTExpiredError);
      await expect(app.jwtUtils.verifyAccessToken(realms.a, await expired('JWT'))).rejects.toThrow(
        'not an access token'
      );
    } finally {
      await app.close();
    }
  });

  it('pins the realm issuer, whatever the key', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const foreign = await signWithPem(realms.realmAKey, { iss: ISSUER_B, typ: 'at+jwt' });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, foreign)).rejects.toThrow(
        JWTInvalidError
      );
    } finally {
      await app.close();
    }
  });

  it('holds the audience to the one asked for', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const token = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      await expect(
        app.jwtUtils.verifyAccessToken(realms.a, token, { audience: 'client-1' })
      ).resolves.toMatchObject({ sub: 'user-1' });
      await expect(
        app.jwtUtils.verifyAccessToken(realms.a, token, { audience: 'client-2' })
      ).rejects.toThrow(JWTInvalidError);
    } finally {
      await app.close();
    }
  });
});

describe('verifying across a rotation (#492)', () => {
  /** The `kid`s of the realm's JWKS. */
  async function jwksKids(app: FastifyInstance, realm: TokenRealm): Promise<unknown[]> {
    return (await app.jwtUtils.getJwks(realm)).keys.map((key) => key['kid']);
  }

  it('verifies a token the retired key signed at requireJwt, and signs new tokens with the new kid', async () => {
    // The signer reads the store on every call, so the rotation shows at once.
    const realms = await createRealms({ refreshIntervalMs: 0 });
    const app = await buildTestApp(realms);
    try {
      const before = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      const oldKid = header(before)['kid'];

      const rotation = await realms.signer.rotateTokenKeys(realms.a.id);
      expect(rotation.retired.map((key) => key.kid)).toEqual([oldKid]);
      const [{ kid: newKid }] = rotation.activated;

      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${before}` },
      });
      expect(response.statusCode, response.body).toBe(200);
      expect(response.json()).toMatchObject({ sub: 'user-1', iss: ISSUER_A });

      const after = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      expect(header(after)['kid']).toBe(newKid);
      await expect(app.jwtUtils.verifyAccessToken(realms.a, after)).resolves.toBeDefined();
      expect(await jwksKids(app, realms.a)).toEqual(expect.arrayContaining([oldKid, newKid]));
    } finally {
      await app.close();
    }
  });

  it('refuses a token the retired key signed once its retention has ended', async () => {
    const realms = await createRealms({ refreshIntervalMs: 0 });
    const app = await buildTestApp(realms);
    try {
      const before = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      await realms.signer.rotateTokenKeys(realms.a.id, { retiredRetentionMs: 0 });

      await expect(app.jwtUtils.verifyAccessToken(realms.a, before)).rejects.toThrow(
        'no key of this realm verifies it'
      );
      expect(await jwksKids(app, realms.a)).not.toContain(header(before)['kid']);
    } finally {
      await app.close();
    }
  });

  it('verifies a token with no kid against the imported key after that key retired', async () => {
    const realms = await createRealms({ refreshIntervalMs: 0 });
    const app = await buildTestApp(realms);
    try {
      const legacy = await signWithPem(realms.realmAKey, { iss: ISSUER_A, aud: 'client-1' });
      expect(header(legacy)).not.toHaveProperty('kid');
      await realms.signer.rotateTokenKeys(realms.a.id);
      await expect(app.jwtUtils.verifyAccessToken(realms.a, legacy)).resolves.toMatchObject({
        sub: 'user-1',
      });
    } finally {
      await app.close();
    }
  });

  it("refuses a token with no kid once the imported key's retention has ended", async () => {
    const realms = await createRealms({ refreshIntervalMs: 0 });
    const app = await buildTestApp(realms);
    try {
      const legacy = await signWithPem(realms.realmAKey, { iss: ISSUER_A, aud: 'client-1' });
      await realms.signer.rotateTokenKeys(realms.a.id, { retiredRetentionMs: 0 });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, legacy)).rejects.toThrow(
        'no key of this realm verifies it'
      );
    } finally {
      await app.close();
    }
  });

  it('verifies both halves of a hybrid token signed before a rotation of the pair', async () => {
    const realms = await createRealms({ hybridSigning: true, refreshIntervalMs: 0 });
    const app = await buildTestApp(realms, {
      hybridSigningEnabled: true,
      enabledSignatureAlgorithms: PQC_ENABLED,
    });
    try {
      const before = await app.jwtUtils.signHybridAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      const rotation = await realms.signer.rotateTokenKeys(realms.a.id);
      // Both keys of the pair rotate together (ADR-005).
      expect(rotation.retired.map((key) => key.kid).sort()).toEqual(
        [header(before.token)['kid'], header(before.token)['pqc_kid']].sort()
      );
      expect(rotation.activated.map((key) => key.algorithm)).toEqual(['EdDSA', 'ML-DSA-65']);

      await expect(
        app.jwtUtils.verifyHybridAccessToken(realms.a, before, { requirePqc: true })
      ).resolves.toMatchObject({ sub: 'user-1' });

      const after = await app.jwtUtils.signHybridAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      expect(header(after.token)).toMatchObject({
        kid: rotation.activated[0].kid,
        pqc_kid: rotation.activated[1].kid,
      });
      await expect(
        app.jwtUtils.verifyHybridAccessToken(realms.a, after, { requirePqc: true })
      ).resolves.toMatchObject({ sub: 'user-1' });

      // The ML-DSA half is checked with the key its signed pqc_kid names: the
      // new pair's signature does not pass for the old token.
      await expect(
        app.jwtUtils.verifyHybridAccessToken(
          realms.a,
          { ...before, pqcSignature: after.pqcSignature },
          { requirePqc: true }
        )
      ).rejects.toThrow();
    } finally {
      await app.close();
    }
  });
});

describe('the plugin holds no private key (#491)', () => {
  it('takes no key option and imports only public verification keys', async () => {
    const realms = await createRealms({ rs256: true });
    // Warm the signer, which holds the realm's keys by design, so its own
    // imports happen before the watch starts.
    await realms.signer.signer.signJws('local', {
      realmId: realms.a.id,
      purpose: 'token_signing',
      typ: 'at+jwt',
      claims: { sub: 'warm-up' },
    });
    await realms.signer.signer.signJws('local', {
      realmId: realms.a.id,
      purpose: 'token_signing',
      typ: 'JWT',
      algorithm: 'RS256',
      claims: { sub: 'warm-up' },
    });
    const importKey = vi.spyOn(crypto.subtle, 'importKey');

    const app = await buildTestApp(realms);
    try {
      const token = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      await app.jwtUtils.signIdToken(realms.a, { sub: 'user-1', audience: 'client-1' });
      await app.jwtUtils.verifyAccessToken(realms.a, token);

      // Every key the plugin imported is a public key that only verifies.
      expect(importKey).toHaveBeenCalled();
      for (const [format, keyData, , , usages] of importKey.mock.calls) {
        expect(format).toBe('jwk');
        expect(keyData).not.toHaveProperty('d');
        expect(usages).toEqual(['verify']);
      }

      // Nothing reachable from the decorators is a private key.
      const seen = new Set<unknown>();
      const privateKeys: unknown[] = [];
      const walk = (value: unknown): void => {
        if (value === null || typeof value !== 'object' || seen.has(value)) return;
        seen.add(value);
        if (
          (value instanceof CryptoKey && value.type === 'private') ||
          (value instanceof KeyObject && value.type === 'private')
        ) {
          privateKeys.push(value);
          return;
        }
        for (const member of Object.values(value)) walk(member);
      };
      walk(app.jwtUtils);
      expect(privateKeys).toEqual([]);
    } finally {
      await app.close();
    }
  });
});

describe('a signer that only reads published keys (a process without the signer role, #495)', () => {
  it("passes the signer's 503 on for every signature and still verifies the realm's tokens", async () => {
    const realms = await createRealms();
    const issuing = await buildTestApp(realms);
    const token = await issuing.jwtUtils.signAccessToken(realms.a, {
      sub: 'user-1',
      clientId: 'client-1',
    });
    await issuing.close();

    const refuse = (): Promise<never> =>
      Promise.reject(
        new TemporarilyUnavailableError(60, { reason: 'signer_service_not_reachable' })
      );
    const verifyOnly = await buildTestApp({
      ...realms,
      signer: {
        ...realms.signer,
        signer: {
          signJws: refuse,
          signHybrid: refuse,
          getVerificationKeys: realms.signer.signer.getVerificationKeys,
          getJwks: realms.signer.signer.getJwks,
        } as unknown as TestSigner['signer'],
      },
    });
    try {
      await expect(
        verifyOnly.jwtUtils.signAccessToken(realms.a, { sub: 'user-1', clientId: 'client-1' })
      ).rejects.toBeInstanceOf(TemporarilyUnavailableError);
      await expect(
        verifyOnly.jwtUtils.signIdToken(realms.a, { sub: 'user-1', audience: 'client-1' })
      ).rejects.toBeInstanceOf(TemporarilyUnavailableError);

      await expect(verifyOnly.jwtUtils.verifyAccessToken(realms.a, token)).resolves.toMatchObject({
        sub: 'user-1',
        iss: ISSUER_A,
      });
      await expect(verifyOnly.jwtUtils.verifyAccessToken(realms.b, token)).rejects.toBeInstanceOf(
        JWTInvalidError
      );
      const response = await verifyOnly.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${token}` },
      });
      expect(response.statusCode).toBe(200);
      expect((await verifyOnly.jwtUtils.getJwks(realms.a)).keys.length).toBeGreaterThan(0);
    } finally {
      await verifyOnly.close();
    }
  });
});

describe('hybrid issuance through the signer (#275, #491)', () => {
  it('refuses to register hybrid signing that SIGNING_ALGORITHM_MODE does not enable', async () => {
    const realms = await createRealms();
    const app = Fastify({ logger: false });
    await expect(
      app.register(jwtPlugin, {
        signer: realms.signer.signer,
        requestRealm: () => realms.a,
        accessTokenLifespan: 900,
        refreshTokenLifespan: 86400,
        hybridSigningEnabled: true,
        enabledSignatureAlgorithms: ['EdDSA'],
      })
    ).rejects.toThrow(/hybridSigningEnabled requires .*ML-DSA-65/);
    await app.close();
  });

  it('stamps kid and pqc_kid, and round-trips through verification in the realm only', async () => {
    const realms = await createRealms({ hybridSigning: true });
    const app = await buildTestApp(realms, {
      hybridSigningEnabled: true,
      enabledSignatureAlgorithms: PQC_ENABLED,
    });
    try {
      expect(app.jwtUtils.isHybridSigningEnabled()).toBe(true);
      const hybrid = await app.jwtUtils.signHybridAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });

      expect(header(hybrid.token)).toEqual({
        alg: 'EdDSA',
        kid: await activeKid(realms, realms.a, 'EdDSA'),
        typ: 'at+jwt',
        pqc_alg: 'ML-DSA-65',
        pqc_kid: await activeKid(realms, realms.a, 'ML-DSA-65'),
      });
      expect(payload(hybrid.token)['iss']).toBe(ISSUER_A);

      await expect(
        app.jwtUtils.verifyHybridAccessToken(realms.a, hybrid, { requirePqc: true })
      ).resolves.toMatchObject({ sub: 'user-1' });
      await expect(
        app.jwtUtils.verifyHybridAccessToken({ ...realms.b, issuer: ISSUER_A }, hybrid, {
          requirePqc: true,
        })
      ).rejects.toThrow();
      // The bearer token is an ordinary Ed25519 JWS that verifies classically too.
      await expect(app.jwtUtils.verifyAccessToken(realms.a, hybrid.token)).resolves.toMatchObject({
        sub: 'user-1',
      });
    } finally {
      await app.close();
    }
  });

  it('refuses a hybrid token of the realm that is not an access token (RFC 9068 typ)', async () => {
    const realms = await createRealms({ hybridSigning: true });
    const app = await buildTestApp(realms, {
      hybridSigningEnabled: true,
      enabledSignatureAlgorithms: PQC_ENABLED,
    });
    try {
      const now = Math.floor(Date.now() / 1000);
      // A hybrid ID token, signed by the realm's own hybrid pair.
      const idToken = await realms.signer.signer.signHybrid('local', {
        realmId: realms.a.id,
        typ: 'JWT',
        claims: { sub: 'user-1', aud: 'client-1', iat: now, exp: now + 900 },
      });
      expect(header(idToken.token)['typ']).toBe('JWT');
      await expect(
        app.jwtUtils.verifyHybridAccessToken(realms.a, idToken, { requirePqc: true })
      ).rejects.toThrow('not an access token');
    } finally {
      await app.close();
    }
  });

  it('refuses hybrid issuance when the switch is off, and PQC verification without ML-DSA-65', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      expect(app.jwtUtils.isHybridSigningEnabled()).toBe(false);
      await expect(
        app.jwtUtils.signHybridAccessToken(realms.a, { sub: 'user-1', clientId: 'client-1' })
      ).rejects.toThrow('Hybrid signing is not enabled on this server.');
      await expect(
        app.jwtUtils.verifyHybridAccessToken(
          realms.a,
          { token: 'a.b.c', pqcSignature: 'x', pqcAlg: 'ML-DSA-65' },
          { requirePqc: true }
        )
      ).rejects.toThrow('PQC verification is not configured on this server');
    } finally {
      await app.close();
    }
  });
});

/**
 * DPoP at the routes `requireJwt` protects (RFC 9449 §7, #480). The plugin
 * applies the two rules that need no verifier: a DPoP-bound token is never a
 * Bearer token (§7.2), and the DPoP scheme needs a bound token. The proof
 * itself is the host app's `verifyDpopProof`, stubbed here.
 */
describe('requireJwt and DPoP (RFC 9449 §7, #480)', () => {
  const JKT = '0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I';

  async function buildDpopApp(
    verifyDpopProof?: (request: unknown, token: string, claims: { cnf?: unknown }) => Promise<void>
  ) {
    const realms = await createRealms();
    const app = await buildTestApp(
      realms,
      verifyDpopProof === undefined ? {} : { verifyDpopProof }
    );
    const sign = async (bound: boolean) =>
      app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
        ...(bound ? { cnf: { jkt: JKT } } : {}),
      });
    return { app, sign };
  }

  it('refuses a DPoP-bound token sent as Bearer, with DPoP on or off (§7.2)', async () => {
    for (const verify of [undefined, async () => undefined]) {
      const { app, sign } = await buildDpopApp(verify);
      try {
        const response = await app.inject({
          method: 'GET',
          url: '/protected',
          headers: { authorization: `Bearer ${await sign(true)}` },
        });
        expect(response.statusCode).toBe(401);
        expect(response.json().error).toBe(
          'A DPoP-bound access token cannot be used as a Bearer token'
        );
      } finally {
        await app.close();
      }
    }
  });

  it('reads the DPoP scheme as no credential when the app verifies no proofs', async () => {
    const { app, sign } = await buildDpopApp();
    try {
      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `DPoP ${await sign(true)}` },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json()).toMatchObject({
        code: 'UNAUTHORIZED',
        error: 'Missing or malformed Authorization header',
      });
      expect(app.jwtUtils.extractCredentialFromHeader('DPoP abc')).toBeNull();
    } finally {
      await app.close();
    }
  });

  it('accepts a bound token under the DPoP scheme once the proof check passes', async () => {
    const calls: Array<{ token: string; cnf: unknown }> = [];
    const { app, sign } = await buildDpopApp(async (_request, token, claims) => {
      calls.push({ token, cnf: claims.cnf });
    });
    try {
      const token = await sign(true);
      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `DPoP ${token}` },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ sub: 'user-1', cnf: { jkt: JKT } });
      expect(calls).toEqual([{ token, cnf: { jkt: JKT } }]);
    } finally {
      await app.close();
    }
  });

  it('refuses the request when the proof check throws', async () => {
    const { app, sign } = await buildDpopApp(async () => {
      throw new JWTInvalidError('proof refused');
    });
    try {
      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `DPoP ${await sign(true)}` },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json().error).toBe('proof refused');
    } finally {
      await app.close();
    }
  });

  it('refuses an unbound token under the DPoP scheme without checking a proof', async () => {
    let called = false;
    const { app, sign } = await buildDpopApp(async () => {
      called = true;
    });
    try {
      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `DPoP ${await sign(false)}` },
      });
      expect(response.statusCode).toBe(401);
      expect(response.json().error).toBe('The access token is not bound to a DPoP key');
      expect(called).toBe(false);
    } finally {
      await app.close();
    }
  });

  it('still accepts an unbound Bearer token with DPoP on', async () => {
    const { app, sign } = await buildDpopApp(async () => undefined);
    try {
      const response = await app.inject({
        method: 'GET',
        url: '/protected',
        headers: { authorization: `Bearer ${await sign(false)}` },
      });
      expect(response.statusCode).toBe(200);
      expect(response.json()).toMatchObject({ sub: 'user-1', cnf: null });
    } finally {
      await app.close();
    }
  });
});

describe('RFC 9068 typ rollout switch (#283)', () => {
  it('signs access tokens with typ: at+jwt and ID tokens with typ: JWT', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      // Both are signed with the SAME key and verify against the SAME JWKS
      // entry — the reason #283 exists. Assert them together so the pair can
      // never drift into being indistinguishable.
      const accessToken = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      const idToken = await app.jwtUtils.signIdToken(realms.a, {
        sub: 'user-1',
        audience: 'client-1',
      });

      expect(header(accessToken)['typ']).toBe('at+jwt');
      expect(header(idToken)['typ']).toBe('JWT');
      expect(header(accessToken)['kid']).toBe(header(idToken)['kid']);
    } finally {
      await app.close();
    }
  });

  it('rejects an ID token presented as an access token, audience held constant', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      // `aud` is `client-1` on BOTH tokens, so the audience check is satisfied
      // either way and cannot be what rejects — only `typ` can.
      const idToken = await app.jwtUtils.signIdToken(realms.a, {
        sub: 'user-1',
        audience: 'client-1',
      });
      const accessToken = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });

      await expect(
        app.jwtUtils.verifyAccessToken(realms.a, accessToken, { audience: 'client-1' })
      ).resolves.toMatchObject({ sub: 'user-1' });
      await expect(
        app.jwtUtils.verifyAccessToken(realms.a, idToken, { audience: 'client-1' })
      ).rejects.toThrow(/typ is not at\+jwt/);
    } finally {
      await app.close();
    }
  });

  it('accepts a legacy typ-less token when the switch is off (default)', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms);
    try {
      const legacy = await signWithPem(realms.realmAKey, { iss: ISSUER_A });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, legacy)).resolves.toMatchObject({
        sub: 'user-1',
      });
    } finally {
      await app.close();
    }
  });

  it('rejects a legacy typ-less token when the operator flips the switch on', async () => {
    const realms = await createRealms();
    const app = await buildTestApp(realms, { requireAccessTokenTyp: true });
    try {
      const legacy = await signWithPem(realms.realmAKey, { iss: ISSUER_A });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, legacy)).rejects.toThrow(
        JWTInvalidError
      );

      // ...and strict mode does not over-reject: a properly typed token still
      // passes under the same setting.
      const good = await app.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      await expect(app.jwtUtils.verifyAccessToken(realms.a, good)).resolves.toMatchObject({
        sub: 'user-1',
      });
    } finally {
      await app.close();
    }
  });
});

describe('RFC 9068 typ rollout switch at requireJwt (#283)', () => {
  it('applies the switch at the plugin seam, so requireJwt refuses a typ-less token too', async () => {
    const realms = await createRealms();
    const strict = await buildTestApp(realms, { requireAccessTokenTyp: true });
    const lenient = await buildTestApp(realms);
    try {
      const legacy = await signWithPem(realms.realmAKey, { iss: ISSUER_A });
      const typed = await strict.jwtUtils.signAccessToken(realms.a, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      const call = (app: FastifyInstance, token: string) =>
        app.inject({
          method: 'GET',
          url: '/protected',
          headers: { authorization: `Bearer ${token}` },
        });

      expect((await call(lenient, legacy)).statusCode).toBe(200);
      const refused = await call(strict, legacy);
      expect(refused.statusCode).toBe(401);
      expect(refused.json()).toMatchObject({ code: 'INVALID_ACCESS_TOKEN' });
      expect((await call(strict, typed)).statusCode).toBe(200);
    } finally {
      await strict.close();
      await lenient.close();
    }
  });
});

/**
 * `verifyRequestAccessToken` under a route's own policy (#509): the API family
 * guards require `typ` whatever the rollout switch says, and take the issuer
 * rule as a hook. Neither may skip a check `requireJwt` makes.
 */
describe('verifyRequestAccessToken policy (#509)', () => {
  const OTHER_ISSUER = 'https://other.test.example.com';

  async function appWith(options: { revoked?: string } = {}) {
    const realms = await createRealms();
    const app = await buildTestApp(realms, {
      isTokenRevoked: (jti) => jti !== undefined && jti === options.revoked,
    });
    return { app, realms };
  }

  /** A request of realm A carrying `token` as a Bearer credential. */
  function requestWith(token: string): FastifyRequest {
    return { headers: { authorization: `Bearer ${token}` } } as FastifyRequest;
  }

  it('requires typ: at+jwt when the policy asks, though the rollout switch is off', async () => {
    const { app, realms } = await appWith();
    try {
      const typless = await signWithPem(realms.realmAKey, { iss: ISSUER_A });
      await expect(app.verifyRequestAccessToken(requestWith(typless))).resolves.toMatchObject({
        sub: 'user-1',
      });
      await expect(
        app.verifyRequestAccessToken(requestWith(typless), { requireTyp: true })
      ).rejects.toThrow(JWTInvalidError);

      const typed = await signWithPem(realms.realmAKey, { iss: ISSUER_A, typ: 'at+jwt' });
      await expect(
        app.verifyRequestAccessToken(requestWith(typed), { requireTyp: true })
      ).resolves.toMatchObject({ sub: 'user-1' });
    } finally {
      await app.close();
    }
  });

  it('pins the realm issuer when the policy names no issuer rule', async () => {
    const { app, realms } = await appWith();
    try {
      const foreign = await signWithPem(realms.realmAKey, { iss: OTHER_ISSUER, typ: 'at+jwt' });
      await expect(app.verifyRequestAccessToken(requestWith(foreign))).rejects.toThrow(
        JWTInvalidError
      );
    } finally {
      await app.close();
    }
  });

  it('lets the issuer rule decide, with the verified iss and the request', async () => {
    const { app, realms } = await appWith();
    try {
      const seen: [string, FastifyRequest][] = [];
      const acceptOther = (issuer: string, request: FastifyRequest) => {
        seen.push([issuer, request]);
        return issuer === OTHER_ISSUER;
      };
      const request = requestWith(await signWithPem(realms.realmAKey, { iss: OTHER_ISSUER }));
      await expect(
        app.verifyRequestAccessToken(request, { acceptIssuer: acceptOther })
      ).resolves.toMatchObject({ iss: OTHER_ISSUER });
      expect(seen).toEqual([[OTHER_ISSUER, request]]);

      const own = await signWithPem(realms.realmAKey, { iss: ISSUER_A });
      await expect(
        app.verifyRequestAccessToken(requestWith(own), { acceptIssuer: acceptOther })
      ).rejects.toThrow('Access token issuer is not accepted here');
    } finally {
      await app.close();
    }
  });

  it("verifies with the request realm's keys whatever the issuer rule", async () => {
    const { app, realms } = await appWith();
    try {
      let calls = 0;
      const acceptAny = async () => {
        calls += 1;
        return true;
      };
      const tokenOfB = await app.jwtUtils.signAccessToken(realms.b, {
        sub: 'user-1',
        clientId: 'client-1',
      });
      await expect(
        app.verifyRequestAccessToken(requestWith(tokenOfB), { acceptIssuer: acceptAny })
      ).rejects.toThrow(JWTInvalidError);
      expect(calls).toBe(0);
    } finally {
      await app.close();
    }
  });

  it('refuses a token with no iss, or a bad signature, before the issuer rule runs', async () => {
    const { app, realms } = await appWith();
    try {
      let calls = 0;
      const acceptAny = async () => {
        calls += 1;
        return true;
      };
      const noIssuer = await signWithPem(realms.realmAKey, {});
      await expect(
        app.verifyRequestAccessToken(requestWith(noIssuer), { acceptIssuer: acceptAny })
      ).rejects.toThrow(JWTInvalidError);

      const forged = await signWithPem(ed25519Pem(), { iss: ISSUER_A });
      await expect(
        app.verifyRequestAccessToken(requestWith(forged), { acceptIssuer: acceptAny })
      ).rejects.toThrow(JWTInvalidError);
      expect(calls).toBe(0);
    } finally {
      await app.close();
    }
  });

  it('still refuses a revoked token and a missing credential under a policy', async () => {
    const { app, realms } = await appWith({ revoked: 'jti-revoked' });
    const policy = { acceptIssuer: () => true, requireTyp: true };
    try {
      const revoked = await signWithPem(realms.realmAKey, {
        iss: ISSUER_A,
        typ: 'at+jwt',
        jti: 'jti-revoked',
      });
      await expect(app.verifyRequestAccessToken(requestWith(revoked), policy)).rejects.toThrow(
        'Token has been revoked'
      );
      // No credential is not a refused token (RFC 6750 §3.1), under a policy too.
      await expect(
        app.verifyRequestAccessToken({ headers: {} } as FastifyRequest, policy)
      ).rejects.toBeInstanceOf(MissingAccessTokenError);
    } finally {
      await app.close();
    }
  });

  it('leaves request.jwtPayload to the caller', async () => {
    const { app, realms } = await appWith();
    try {
      const request = requestWith(
        await signWithPem(realms.realmAKey, { iss: ISSUER_A, typ: 'at+jwt' })
      );
      await app.verifyRequestAccessToken(request);
      expect(request.jwtPayload).toBeUndefined();
    } finally {
      await app.close();
    }
  });
});
