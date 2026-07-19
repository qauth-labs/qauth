import {
  getSignatureBackend,
  type MlDsaKey,
  registerSignatureBackend,
  resetSignatureBackends,
} from '@qauth-labs/core-crypto';
import {
  generateEdDSAKeyPair,
  importPrivateKey,
  selectJwksKey,
  signAccessToken,
} from '@qauth-labs/server-jwt';
import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import type { FastifyInstance } from 'fastify';
import Fastify from 'fastify';
import { exportPKCS8, exportSPKI, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { jwtPlugin } from './fastify-plugin-jwt';

/** Operator-enabled algorithm set (SIGNING_ALGORITHM_MODE=ed25519+ml-dsa-65). */
const PQC_ENABLED = ['EdDSA', 'ML-DSA-65'] as const;

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

  it('getJwks() is EdDSA-only (single OKP key) when no ML-DSA seed is configured (#246)', async () => {
    const { app } = await buildTestApp();
    try {
      const jwks = await app.jwtUtils.getJwks();
      expect(jwks.keys).toHaveLength(1);
      expect(jwks.keys.every((k) => (k as { kty?: string }).kty !== 'AKP')).toBe(true);
    } finally {
      await app.close();
    }
  });

  it('getJwks() publishes an AKP key beside the OKP key when an ML-DSA seed is configured (#246)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair(true);
    const privateKeyPem = await exportPKCS8(privateKey);
    const publicKeyPem = await exportSPKI(publicKey);
    const mlDsa = getSignatureBackend('ML-DSA-65', PQC_ENABLED).generateKeyPair({
      extractable: true,
    });
    const seed = getSignatureBackend('ML-DSA-65', PQC_ENABLED).exportKey(mlDsa.privateKey);

    const app = Fastify({ logger: false });
    await app.register(jwtPlugin, {
      privateKey: privateKeyPem,
      publicKey: publicKeyPem,
      issuer: 'https://auth.test.example.com',
      accessTokenLifespan: 900,
      refreshTokenLifespan: 86400,
      keyId: 'ed-1',
      mlDsaSeed: seed,
      mlDsaKeyId: 'ed-1-mldsa',
      enabledSignatureAlgorithms: PQC_ENABLED,
    });
    try {
      const jwks = await app.jwtUtils.getJwks();
      expect(jwks.keys).toHaveLength(2);

      const okp = jwks.keys.find((k) => (k as { kty?: string }).kty === 'OKP') as
        | Record<string, unknown>
        | undefined;
      const akp = jwks.keys.find((k) => (k as { kty?: string }).kty === 'AKP') as
        | Record<string, unknown>
        | undefined;
      expect(okp?.['alg']).toBe('EdDSA');
      expect(akp?.['alg']).toBe('ML-DSA-65');
      expect(akp?.['kid']).toBe('ed-1-mldsa');
      // The AKP entry carries only the public key, never private material.
      expect(akp).not.toHaveProperty('priv');
      expect(akp).not.toHaveProperty('d');
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

describe('jwtPlugin — PQC backend gating, rotation, and seed hygiene (#248 F7/F9/F10)', () => {
  const mlDsaBackend = getSignatureBackend('ML-DSA-65', PQC_ENABLED);

  async function edPems() {
    const { privateKey, publicKey } = await generateEdDSAKeyPair(true);
    return {
      privateKeyPem: await exportPKCS8(privateKey),
      publicKeyPem: await exportSPKI(publicKey),
    };
  }

  function freshMlDsa() {
    const pair = mlDsaBackend.generateKeyPair({ extractable: true });
    return {
      seed: mlDsaBackend.exportKey(pair.privateKey),
      publicKey: mlDsaBackend.exportKey(pair.publicKey),
    };
  }

  function baseOptions(pems: { privateKeyPem: string; publicKeyPem: string }) {
    return {
      privateKey: pems.privateKeyPem,
      publicKey: pems.publicKeyPem,
      issuer: 'https://auth.test.example.com',
      accessTokenLifespan: 900,
      refreshTokenLifespan: 86400,
    };
  }

  it('F7: fails boot when an ML-DSA seed is set without the operator allowlist', async () => {
    const pems = await edPems();
    const app = Fastify({ logger: false });
    // Omitting the allowlist is exactly the hardcoded-['ML-DSA-65'] bypass the
    // finding is about — it must be impossible to configure, not defaulted.
    await expect(
      app.register(jwtPlugin, {
        ...baseOptions(pems),
        keyId: 'ed-1',
        mlDsaSeed: freshMlDsa().seed,
        mlDsaKeyId: 'mldsa-1',
      })
    ).rejects.toThrow(/enabledSignatureAlgorithms.*is required/s);
    await app.close();
  });

  it('F7: fails boot when SIGNING_ALGORITHM_MODE has not enabled ML-DSA-65', async () => {
    const pems = await edPems();
    const app = Fastify({ logger: false });
    await expect(
      app.register(jwtPlugin, {
        ...baseOptions(pems),
        keyId: 'ed-1',
        mlDsaSeed: freshMlDsa().seed,
        mlDsaKeyId: 'mldsa-1',
        // Classical-only deployment: the ML-DSA key must not be publishable.
        enabledSignatureAlgorithms: ['EdDSA'],
      })
    ).rejects.toThrow(/'ML-DSA-65' is not enabled/);
    await app.close();
  });

  it('F10: zeroizes the transient private key right after boot-time derivation', async () => {
    const pems = await edPems();
    const { seed } = freshMlDsa();
    // Capture the exact MlDsaKey the plugin derives from, via the backend seam,
    // so zeroization is observable rather than merely assumed.
    let imported: MlDsaKey | undefined;
    registerSignatureBackend({
      ...mlDsaBackend,
      importKey(encoded, kind, options) {
        const key = mlDsaBackend.importKey(encoded, kind, options);
        if (kind === 'private') imported = key;
        return key;
      },
    });
    const app = Fastify({ logger: false });
    try {
      await app.register(jwtPlugin, {
        ...baseOptions(pems),
        keyId: 'ed-1',
        mlDsaSeed: seed,
        mlDsaKeyId: 'mldsa-1',
        enabledSignatureAlgorithms: PQC_ENABLED,
      });

      expect(imported).toBeDefined();
      // The seed is overwritten and the key marked dead the moment boot-time
      // derivation completes — it must not stay resident for the process life.
      expect(() => imported?.seed()).toThrow(/destroyed/);
      expect(() => imported?.material()).toThrow(/destroyed/);

      // ...and the JWKS it produced is still correct.
      const { keys } = await app.jwtUtils.getJwks();
      expect(selectJwksKey(keys, { kid: 'mldsa-1', alg: 'ML-DSA-65' })).toBeDefined();
    } finally {
      resetSignatureBackends();
      await app.close();
    }
  });

  it('F10: the configured seed is not retained — JWKS exposes public material only', async () => {
    const pems = await edPems();
    const { seed } = freshMlDsa();
    const app = Fastify({ logger: false });
    await app.register(jwtPlugin, {
      ...baseOptions(pems),
      keyId: 'ed-1',
      mlDsaSeed: seed,
      mlDsaKeyId: 'mldsa-1',
      enabledSignatureAlgorithms: PQC_ENABLED,
    });
    try {
      const jwks = await app.jwtUtils.getJwks();
      const serialized = JSON.stringify(jwks);
      // The transient private key is zeroized right after derivation, so the
      // seed exists nowhere in what the server can still serve.
      expect(serialized).not.toContain(seed);
      expect(serialized).not.toContain('priv');
      expect(serialized).not.toContain('"d"');
    } finally {
      await app.close();
    }
  });

  it('F9: publishes retired Ed25519 and ML-DSA keys under their own kids', async () => {
    const pems = await edPems();
    const retiredEd = await generateEdDSAKeyPair(true);
    const retiredMlDsa = freshMlDsa();
    const app = Fastify({ logger: false });
    await app.register(jwtPlugin, {
      ...baseOptions(pems),
      keyId: 'ed-2026',
      mlDsaSeed: freshMlDsa().seed,
      mlDsaKeyId: 'mldsa-2026',
      enabledSignatureAlgorithms: PQC_ENABLED,
      retiredKeys: [{ publicKey: await exportSPKI(retiredEd.publicKey), keyId: 'ed-2025' }],
      retiredMlDsaPublicKeys: [{ publicKey: retiredMlDsa.publicKey, keyId: 'mldsa-2025' }],
    });
    try {
      const { keys } = await app.jwtUtils.getJwks();
      expect(keys).toHaveLength(4);

      // Every published key resolves by its OWN (kid, alg) — the rotation
      // property that lets tokens signed before the rotation keep verifying.
      for (const [kid, alg] of [
        ['ed-2026', 'EdDSA'],
        ['ed-2025', 'EdDSA'],
        ['mldsa-2026', 'ML-DSA-65'],
        ['mldsa-2025', 'ML-DSA-65'],
      ] as const) {
        expect(selectJwksKey(keys, { kid, alg })).toBeDefined();
      }
      // ...and never under the wrong algorithm.
      expect(selectJwksKey(keys, { kid: 'mldsa-2025', alg: 'EdDSA' })).toBeUndefined();
      expect(selectJwksKey(keys, { kid: 'ed-2025', alg: 'ML-DSA-65' })).toBeUndefined();

      // Retired ML-DSA keys are public material only.
      expect(JSON.stringify(keys)).not.toContain('priv');
    } finally {
      await app.close();
    }
  });

  it('F9: refuses to SERVE a JWKS whose kids collide across OKP and AKP', async () => {
    const pems = await edPems();
    const app = Fastify({ logger: false });
    await app.register(jwtPlugin, {
      ...baseOptions(pems),
      // Same kid for the Ed25519 and the ML-DSA key: a stock verifier selecting
      // on kid alone could land on the wrong algorithm's key.
      keyId: 'shared-kid',
      mlDsaSeed: freshMlDsa().seed,
      mlDsaKeyId: 'shared-kid',
      enabledSignatureAlgorithms: PQC_ENABLED,
    });
    try {
      await expect(app.jwtUtils.getJwks()).rejects.toThrow(/duplicate kid 'shared-kid'/);
    } finally {
      await app.close();
    }
  });

  it('F9: refuses to SERVE a JWKS whose retired kid collides with the active one', async () => {
    const pems = await edPems();
    const retiredEd = await generateEdDSAKeyPair(true);
    const app = Fastify({ logger: false });
    await app.register(jwtPlugin, {
      ...baseOptions(pems),
      keyId: 'ed-2026',
      retiredKeys: [{ publicKey: await exportSPKI(retiredEd.publicKey), keyId: 'ed-2026' }],
    });
    try {
      await expect(app.jwtUtils.getJwks()).rejects.toThrow(/duplicate kid 'ed-2026'/);
    } finally {
      await app.close();
    }
  });

  it('leaves the classical EdDSA-only JWKS untouched (no PQC config, no behaviour change)', async () => {
    const pems = await edPems();
    const app = Fastify({ logger: false });
    await app.register(jwtPlugin, { ...baseOptions(pems), keyId: 'ed-1' });
    try {
      const { keys } = await app.jwtUtils.getJwks();
      expect(keys).toHaveLength(1);
      expect(selectJwksKey(keys, { kid: 'ed-1', alg: 'EdDSA' })).toBeDefined();
    } finally {
      await app.close();
    }
  });
});

describe('jwtPlugin — live hybrid issuance vs seed zeroization (#275 x #248 F10)', () => {
  const PQC_ENABLED_LOCAL = ['EdDSA', 'ML-DSA-65'] as const;

  async function edPemsLocal() {
    const { privateKey, publicKey } = await generateEdDSAKeyPair(true);
    return {
      privateKeyPem: await exportPKCS8(privateKey),
      publicKeyPem: await exportSPKI(publicKey),
    };
  }

  function baseOptionsLocal(pems: { privateKeyPem: string; publicKeyPem: string }) {
    return {
      privateKey: pems.privateKeyPem,
      publicKey: pems.publicKeyPem,
      issuer: 'https://auth.test.example.com',
      accessTokenLifespan: 900,
      refreshTokenLifespan: 86400,
    };
  }

  function freshSeed() {
    const backend = getSignatureBackend('ML-DSA-65', PQC_ENABLED_LOCAL);
    return backend.exportKey(backend.generateKeyPair({ extractable: true }).privateKey);
  }

  // The regression guard for the #275/#276 merge: #276 zeroizes the ML-DSA
  // private key right after deriving the public half (F10), while #275 needs
  // that same key resident to sign. Collapsing the two arms boots cleanly and
  // only fails on the FIRST token issuance — a total /token outage that no
  // boot-time assertion catches. Issue *and* verify here, not just register.
  it('retains the ML-DSA private key when hybrid issuance is ON, and round-trips a token', async () => {
    const pems = await edPemsLocal();
    const app = Fastify({ logger: false });
    try {
      await app.register(jwtPlugin, {
        ...baseOptionsLocal(pems),
        keyId: 'ed-1',
        mlDsaSeed: freshSeed(),
        mlDsaKeyId: 'mldsa-1',
        hybridSigningEnabled: true,
        enabledSignatureAlgorithms: PQC_ENABLED_LOCAL,
      });

      expect(app.jwtUtils.isHybridSigningEnabled()).toBe(true);

      const hybrid = await app.jwtUtils.signHybridAccessToken({
        sub: 'user-1',
        clientId: 'client-1',
      });
      expect(hybrid.pqcSignature.length).toBeGreaterThan(0);

      const claims = await app.jwtUtils.verifyHybridAccessToken(hybrid, {
        requirePqc: true,
        issuer: 'https://auth.test.example.com',
        audience: 'client-1',
      });
      expect(claims.sub).toBe('user-1');
    } finally {
      await app.close();
    }
  });

  // The other arm: with hybrid OFF the F10 property must still hold exactly as
  // #276 asserts it — no signing material survives boot.
  it('still zeroizes the seed when hybrid issuance is OFF (F10 unchanged)', async () => {
    const pems = await edPemsLocal();
    const mlDsaBackendLocal = getSignatureBackend('ML-DSA-65', PQC_ENABLED_LOCAL);
    let imported: MlDsaKey | undefined;
    registerSignatureBackend({
      ...mlDsaBackendLocal,
      importKey(encoded, kind, options) {
        const key = mlDsaBackendLocal.importKey(encoded, kind, options);
        if (kind === 'private') imported = key;
        return key;
      },
    });
    const app = Fastify({ logger: false });
    try {
      await app.register(jwtPlugin, {
        ...baseOptionsLocal(pems),
        keyId: 'ed-1',
        mlDsaSeed: freshSeed(),
        mlDsaKeyId: 'mldsa-1',
        enabledSignatureAlgorithms: PQC_ENABLED_LOCAL,
      });

      expect(imported).toBeDefined();
      expect(() => imported?.seed()).toThrow(/destroyed/);
      expect(app.jwtUtils.isHybridSigningEnabled()).toBe(false);
    } finally {
      resetSignatureBackends();
      await app.close();
    }
  });
});
