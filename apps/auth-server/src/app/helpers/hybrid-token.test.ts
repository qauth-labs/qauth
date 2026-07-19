import { generateKeyPairSync } from 'node:crypto';

import {
  CryptoVerificationError,
  extractJwsSigningInput,
  getSignatureBackend,
  type HybridSignedToken,
  PQC_ALG_ML_DSA_65,
} from '@qauth-labs/core-crypto';
import { jwtPlugin } from '@qauth-labs/fastify-plugin-jwt';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import { getPqcSignature, issueAccessToken } from './hybrid-token';

/**
 * End-to-end coverage for live hybrid issuance + PQC-aware verification
 * (ADR-005 / #275). Everything below runs the REAL crypto stack — a real
 * Ed25519 key, a real ML-DSA-65 seed, the real `jwtPlugin` — against an
 * in-memory Redis double, so the assertions are about actual signatures rather
 * than mocks.
 */

const ISSUER = 'https://auth.test.example.com';
const MLDSA_KID = 'mldsa-test-1';
const noble = getSignatureBackend('ML-DSA-65', ['ML-DSA-65']);

/** A fresh Ed25519 key pair in the PKCS#8 / SPKI PEM form the plugin expects. */
function generateEd25519Pem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });
  return { privateKeyPem: privateKey, publicKeyPem: publicKey };
}

/** Minimal in-memory stand-in for the `fastify.redis` decorator (no TTL clock). */
function createRedisDouble() {
  const store = new Map<string, string>();
  return {
    store,
    setex: vi.fn(async (key: string, _ttl: number, value: string) => {
      store.set(key, value);
      return 'OK';
    }),
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    exists: vi.fn(async (key: string) => (store.has(key) ? 1 : 0)),
  };
}

async function buildApp(opts: { hybrid: boolean }): Promise<{
  app: FastifyInstance;
  redis: ReturnType<typeof createRedisDouble>;
}> {
  const { privateKeyPem, publicKeyPem } = generateEd25519Pem();
  // A real ML-DSA-65 seed in the same base64url export form the config layer
  // resolves from JWT_MLDSA_PRIVATE_KEY.
  const mlDsaPair = noble.generateKeyPair({ extractable: true });
  const mlDsaSeed = noble.exportKey(mlDsaPair.privateKey);

  const app = Fastify();
  const redis = createRedisDouble();
  app.decorate('redis', redis as never);

  await app.register(jwtPlugin, {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    issuer: ISSUER,
    accessTokenLifespan: 900,
    refreshTokenLifespan: 3600,
    ...(opts.hybrid
      ? {
          mlDsaSeed,
          mlDsaKeyId: MLDSA_KID,
          hybridSigningEnabled: true,
          enabledSignatureAlgorithms: ['EdDSA', 'ML-DSA-65'] as const,
        }
      : {}),
  });
  await app.ready();
  return { app, redis };
}

const PAYLOAD = { sub: 'user-1', clientId: 'client-1', scope: 'read' };

describe('#275 — live hybrid issuance', () => {
  it('classical deployment: issues a plain token and stores no PQC material', async () => {
    const { app, redis } = await buildApp({ hybrid: false });
    const token = await issueAccessToken(app, PAYLOAD);

    expect(app.jwtUtils.isHybridSigningEnabled()).toBe(false);
    expect(token.split('.')).toHaveLength(3);
    expect(redis.setex).not.toHaveBeenCalled();

    // The classical verify path is untouched.
    const claims = await app.jwtUtils.verifyAccessToken(token, { issuer: ISSUER });
    expect(claims.sub).toBe('user-1');
    await app.close();
  });

  it('refuses to issue a hybrid token whose PQC signature cannot be stored (#248 F1)', async () => {
    // storePqcSignature must FAIL CLOSED, not return quietly. After F1 made a
    // signed `pqc_alg` binding, a hybrid token with no retrievable signature is
    // not degraded — it is unverifiable at every PQC-aware verifier. Returning
    // it would be exactly the silent downgrade this module prevents.
    const { app } = await buildApp({ hybrid: true });
    // A token carrying no jti has nothing to key the store entry on.
    app.jwtUtils.decodeTokenUnsafe = () =>
      ({ jti: undefined, exp: undefined }) as ReturnType<
        FastifyInstance['jwtUtils']['decodeTokenUnsafe']
      >;

    await expect(issueAccessToken(app, PAYLOAD)).rejects.toThrow(/no jti/);
    await app.close();
  });

  it('refuses to issue a hybrid token that is already expired', async () => {
    const { app } = await buildApp({ hybrid: true });
    app.jwtUtils.decodeTokenUnsafe = () =>
      ({
        jti: 'jti-expired',
        exp: Math.floor(Date.now() / 1000) - 60,
      }) as ReturnType<FastifyInstance['jwtUtils']['decodeTokenUnsafe']>;

    await expect(issueAccessToken(app, PAYLOAD)).rejects.toThrow(/already expired/);
    await app.close();
  });

  it('hybrid deployment: the BEARER stays a small classical JWS (reference delivery, #247)', async () => {
    const { app } = await buildApp({ hybrid: true });
    const token = await issueAccessToken(app, PAYLOAD);

    expect(app.jwtUtils.isHybridSigningEnabled()).toBe(true);
    expect(token.split('.')).toHaveLength(3);
    // The ~4.4 KB PQC signature is NOT inlined; the bearer stays budget-safe.
    expect(token.length).toBeLessThan(1500);
    // And it still verifies with zero PQC awareness (AC#2 compatibility).
    const claims = await app.jwtUtils.verifyAccessToken(token, { issuer: ISSUER });
    expect(claims.sub).toBe('user-1');
    await app.close();
  });

  it('hybrid deployment: stamps the SIGNED pqc_alg / pqc_kid protected header', async () => {
    const { app } = await buildApp({ hybrid: true });
    const token = await issueAccessToken(app, PAYLOAD);

    const header = JSON.parse(
      Buffer.from(token.split('.')[0], 'base64url').toString('utf-8')
    ) as Record<string, unknown>;
    expect(header['alg']).toBe('EdDSA');
    expect(header['pqc_alg']).toBe(PQC_ALG_ML_DSA_65);
    expect(header['pqc_kid']).toBe(MLDSA_KID);
    // Non-critical, so stock verifiers keep working.
    expect(header['crit']).toBeUndefined();
    await app.close();
  });

  it('the stored PQC signature verifies over the token JWS signing-input', async () => {
    const { app } = await buildApp({ hybrid: true });
    const token = await issueAccessToken(app, PAYLOAD);
    const jti = app.jwtUtils.decodeTokenUnsafe(token).jti;

    const stored = await getPqcSignature(app, jti, token);
    expect(stored?.pqcAlg).toBe(PQC_ALG_ML_DSA_65);

    // Verify with the ML-DSA public key the server publishes in JWKS — i.e.
    // exactly the material an external verifier can actually obtain.
    const jwks = await app.jwtUtils.getJwks();
    const akp = jwks.keys.find((k) => (k as { kty?: string }).kty === 'AKP');
    expect(akp).toBeDefined();
    expect((akp as unknown as { kid?: string }).kid).toBe(MLDSA_KID);

    const mlDsaPublic = noble.importKey((akp as unknown as { pub: string }).pub, 'public');
    expect(() =>
      noble.verify(
        mlDsaPublic,
        extractJwsSigningInput(token),
        new Uint8Array(Buffer.from(stored?.pqcSignature ?? '', 'base64url'))
      )
    ).not.toThrow();
    await app.close();
  });

  it('the stored entry TTL tracks the token lifetime, keyed by jti', async () => {
    const { app, redis } = await buildApp({ hybrid: true });
    const token = await issueAccessToken(app, PAYLOAD);
    const jti = app.jwtUtils.decodeTokenUnsafe(token).jti;

    expect(redis.setex).toHaveBeenCalledTimes(1);
    const [key, ttl] = redis.setex.mock.calls[0];
    expect(key).toBe(`pqc-signature:${jti}`);
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(900);
    await app.close();
  });

  it('registering with hybridSigningEnabled but no seed fails fast', async () => {
    const { privateKeyPem, publicKeyPem } = generateEd25519Pem();
    const app = Fastify();
    await expect(
      app
        .register(jwtPlugin, {
          privateKey: privateKeyPem,
          publicKey: publicKeyPem,
          issuer: ISSUER,
          accessTokenLifespan: 900,
          refreshTokenLifespan: 3600,
          hybridSigningEnabled: true,
        })
        .ready()
    ).rejects.toThrow(/hybridSigningEnabled requires mlDsaSeed/);
  });
});

describe('#275 — end-to-end: issue a hybrid token, validate it via introspection', () => {
  let app: FastifyInstance;

  beforeEach(async () => {
    ({ app } = await buildApp({ hybrid: true }));
  });

  it('a resource server reassembles and fully verifies the hybrid token from introspection', async () => {
    // 1. Authorization server issues the token (what the token endpoint does).
    const token = await issueAccessToken(app, PAYLOAD);
    const jti = app.jwtUtils.decodeTokenUnsafe(token).jti;

    // 2. Resource server receives ONLY the bearer, then introspects to fetch
    //    the detached PQC component (the `pqc_signature` field introspect.ts
    //    returns).
    const pqc = await getPqcSignature(app, jti, token);
    expect(pqc).toBeDefined();

    // 3. It reassembles the hybrid token and verifies BOTH components. This is
    //    the full post-quantum validation an RS performs.
    const reassembled: HybridSignedToken = {
      token,
      pqcSignature: pqc?.pqcSignature ?? '',
      pqcAlg: PQC_ALG_ML_DSA_65,
    };
    const claims = await app.jwtUtils.verifyHybridAccessToken(reassembled, {
      issuer: ISSUER,
      requirePqc: true,
    });
    expect(claims.sub).toBe('user-1');
    expect(claims.scope).toBe('read');
  });

  it('F1 e2e: a bearer whose PQC signature was withheld is REJECTED even with requirePqc=false', async () => {
    const token = await issueAccessToken(app, PAYLOAD);

    // An attacker (or a lazy RS) skips introspection and presents the bearer
    // alone. The Ed25519-signed `pqc_alg` header makes that a downgrade, and it
    // must fail regardless of the caller's policy flag.
    await expect(
      app.jwtUtils.verifyHybridAccessToken(
        { token, pqcSignature: '', pqcAlg: PQC_ALG_ML_DSA_65 },
        { issuer: ISSUER, requirePqc: false }
      )
    ).rejects.toThrow(CryptoVerificationError);

    // Meanwhile the CLASSICAL path still accepts it — that is the deliberate
    // AC#2 compatibility guarantee, and precisely why the PQC-aware path must
    // not be permissive.
    await expect(app.jwtUtils.verifyAccessToken(token, { issuer: ISSUER })).resolves.toBeDefined();
  });

  it('F5 e2e: a signature from a foreign ML-DSA key does not verify', async () => {
    const token = await issueAccessToken(app, PAYLOAD);
    const attacker = noble.generateKeyPair({ extractable: true });
    const forged = Buffer.from(
      noble.sign(attacker.privateKey, extractJwsSigningInput(token))
    ).toString('base64url');

    await expect(
      app.jwtUtils.verifyHybridAccessToken(
        { token, pqcSignature: forged, pqcAlg: PQC_ALG_ML_DSA_65 },
        { issuer: ISSUER, requirePqc: true }
      )
    ).rejects.toThrow(CryptoVerificationError);
  });

  it('a PQC signature bound to a DIFFERENT token is rejected (no replay across tokens)', async () => {
    const tokenA = await issueAccessToken(app, PAYLOAD);
    const tokenB = await issueAccessToken(app, { ...PAYLOAD, sub: 'user-2' });
    const pqcB = await getPqcSignature(app, app.jwtUtils.decodeTokenUnsafe(tokenB).jti, tokenB);

    await expect(
      app.jwtUtils.verifyHybridAccessToken(
        { token: tokenA, pqcSignature: pqcB?.pqcSignature ?? '', pqcAlg: PQC_ALG_ML_DSA_65 },
        { issuer: ISSUER, requirePqc: true }
      )
    ).rejects.toThrow(CryptoVerificationError);
  });

  it('getPqcSignature returns undefined for an unknown jti', async () => {
    const token = await issueAccessToken(app, PAYLOAD);
    await expect(getPqcSignature(app, 'no-such-jti', token)).resolves.toBeUndefined();
  });

  it('getPqcSignature skips the store entirely for a token with no signed pqc_alg', async () => {
    // The retrieval gate is a per-TOKEN fact (does its verified header
    // advertise PQC?), never the deployment's current issuance posture — that
    // is what keeps a HYBRID_SIGNING_ENABLED rollback graceful while still
    // costing a classical token zero store round-trips.
    const classical = await buildApp({ hybrid: false });
    const classicalToken = await issueAccessToken(classical.app, PAYLOAD);
    const jti = classical.app.jwtUtils.decodeTokenUnsafe(classicalToken).jti;

    await expect(getPqcSignature(classical.app, jti, classicalToken)).resolves.toBeUndefined();
    expect(classical.redis.get).not.toHaveBeenCalled();
    await classical.app.close();
  });
});
