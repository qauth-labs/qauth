import {
  generateSigningKeyPair,
  getSignatureBackend,
  type HybridVerifyKey,
} from '@qauth-labs/core-crypto';
import { jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  signHybridAccessToken,
  signHybridIdToken,
  verifyHybridAccessToken,
} from './hybrid-jwt-service';
import { buildAccessTokenClaims, signAccessToken, verifyAccessToken } from './jwt-service';

const ISSUER = 'https://auth.example.com';
// Operator-enabled algorithm set (#248 F7/F11) — threaded into every hybrid call.
const PQC_ENABLED = ['EdDSA', 'ML-DSA-65'] as const;
const PQC_BACKEND = { enabledSignatureAlgorithms: PQC_ENABLED };
const noble = getSignatureBackend('ML-DSA-65', PQC_ENABLED);

async function hybridKeys() {
  const ed = await generateSigningKeyPair('EdDSA', { extractable: true });
  const mlDsa = noble.generateKeyPair({ extractable: true });
  return {
    signing: { ed: ed.privateKey, mlDsa: mlDsa.privateKey, edKid: 'k1', mlDsaKid: 'k1-mldsa' },
    verify: { ed: ed.publicKey, mlDsa: mlDsa.publicKey } satisfies HybridVerifyKey,
    edPublic: ed.publicKey,
  };
}

describe('hybrid jwt-service (#245)', () => {
  it('produces a hybrid access token whose classical component stock jose verifies', async () => {
    const { signing, edPublic } = await hybridKeys();
    const hybrid = await signHybridAccessToken(
      { sub: 'user-1', clientId: 'client-1', scope: 'read' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );
    const { payload } = await jwtVerify(hybrid.token, edPublic, { algorithms: ['EdDSA'] });
    expect(payload['sub']).toBe('user-1');
    expect(payload['token_use']).toBe('access');
    expect(payload['scope']).toBe('read');
    expect(hybrid.pqcAlg).toBe('ML-DSA-65');
    // #275 / #248 F5: the key id is carried ONLY in the signed protected
    // header, never as an unsigned transport field.
    expect(hybrid).not.toHaveProperty('pqcKid');
    const { protectedHeader } = await jwtVerify(hybrid.token, edPublic, { algorithms: ['EdDSA'] });
    expect(protectedHeader['pqc_kid']).toBe('k1-mldsa');
  });

  it('shapes claims identically to the classical signer (modulo the per-token jti)', async () => {
    const { signing, edPublic } = await hybridKeys();
    const payload = { sub: 'u', clientId: 'c', email: 'e@x.co', email_verified: true } as const;

    // Classical claim builder (the shared source) vs the decoded hybrid token.
    const { claims: expected } = buildAccessTokenClaims(payload);
    const hybrid = await signHybridAccessToken(payload, signing, ISSUER, 900, PQC_BACKEND);
    const { payload: got } = await jwtVerify(hybrid.token, edPublic, { algorithms: ['EdDSA'] });

    for (const key of ['sub', 'client_id', 'token_use', 'email', 'email_verified'] as const) {
      expect(got[key]).toEqual(expected[key]);
    }
    // jti is per-token (fresh randomUUID each call), so it differs by design.
    expect(typeof got['jti']).toBe('string');
  });

  it('verifyHybridAccessToken round-trips both components', async () => {
    const { signing, verify } = await hybridKeys();
    const hybrid = await signHybridAccessToken(
      { sub: 'user-1', clientId: 'client-1' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );
    const claims = await verifyHybridAccessToken(hybrid, verify, {
      requirePqc: true,
      issuer: ISSUER,
      ...PQC_BACKEND,
    });
    expect(claims['sub']).toBe('user-1');
  });

  it('signHybridIdToken stamps token_use=id and echoes nonce', async () => {
    const { signing, edPublic } = await hybridKeys();
    const hybrid = await signHybridIdToken(
      { sub: 'user-1', audience: 'client-1', nonce: 'n-1' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );
    const { payload } = await jwtVerify(hybrid.token, edPublic, { algorithms: ['EdDSA'] });
    expect(payload['token_use']).toBe('id');
    expect(payload['nonce']).toBe('n-1');
  });

  it('introspection path accepts a hybrid bearer as a reference token (#247 AC#4)', async () => {
    // When hybrid is on, the bearer (`.token`) is still a plain Ed25519 JWS, so
    // the EXACT function introspection calls (`verifyAccessToken`, wired as
    // `fastify.jwtUtils.verifyAccessToken` at introspect.ts) validates it with
    // no PQC awareness. The ~4.4 KB PQC signature is delivered out-of-band.
    const { signing, edPublic } = await hybridKeys();
    const hybrid = await signHybridAccessToken(
      { sub: 'user-1', clientId: 'client-1', scope: 'read' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );
    const claims = await verifyAccessToken(hybrid.token, edPublic, { issuer: ISSUER });
    expect(claims.sub).toBe('user-1');
    expect(claims.scope).toBe('read');
  });

  it('zero-regression: the classical signAccessToken is unchanged (no pqc header member)', async () => {
    const ed = await generateSigningKeyPair('EdDSA', { extractable: true });
    const token = await signAccessToken({ sub: 'u', clientId: 'c' }, ed.privateKey, ISSUER, 900);
    const { protectedHeader } = await jwtVerify(token, ed.publicKey, { algorithms: ['EdDSA'] });
    expect(protectedHeader).toEqual({ alg: 'EdDSA' });
  });
});
