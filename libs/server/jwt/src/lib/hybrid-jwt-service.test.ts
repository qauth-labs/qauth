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
    // `typ` (RFC 9068 §2.1, #283) is expected on EVERY access token, classical
    // or hybrid. What this test guards is that the classical signer picks up no
    // PQC members: an exact match, so a stray `pqc_alg`/`pqc_kid` fails here.
    expect(protectedHeader).toEqual({ alg: 'EdDSA', typ: 'at+jwt' });
  });
});

describe('hybrid jwt-service — RFC 9068 typ (#283 × ADR-005)', () => {
  it('stamps typ: at+jwt alongside pqc_alg / pqc_kid in the SIGNED header', async () => {
    const { signing, edPublic } = await hybridKeys();

    const hybrid = await signHybridAccessToken(
      { sub: 'user-1', clientId: 'client-1' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );

    // All four members must survive together in one Ed25519-signed header: the
    // classical `alg`/`kid`, the #283 `typ`, and the ADR-005 PQC members. A
    // stock jose verifier reads them all, which is the compatibility guarantee.
    const { protectedHeader } = await jwtVerify(hybrid.token, edPublic, { algorithms: ['EdDSA'] });
    expect(protectedHeader).toEqual({
      alg: 'EdDSA',
      typ: 'at+jwt',
      kid: 'k1',
      pqc_alg: 'ML-DSA-65',
      pqc_kid: 'k1-mldsa',
    });
  });

  it('stamps typ: JWT on hybrid ID tokens, keeping the two distinguishable', async () => {
    const { signing, edPublic } = await hybridKeys();

    const hybrid = await signHybridIdToken(
      { sub: 'user-1', audience: 'client-1' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );

    const { protectedHeader } = await jwtVerify(hybrid.token, edPublic, { algorithms: ['EdDSA'] });
    expect(protectedHeader['typ']).toBe('JWT');
    expect(protectedHeader['pqc_alg']).toBe('ML-DSA-65');
  });

  it('leaves the detached ML-DSA signature valid over the typ-bearing header', async () => {
    const { signing, verify } = await hybridKeys();

    // `typ` is inside the JWS signing input, so the detached PQC signature
    // covers it too: if the header and the signature could drift apart, this is
    // where it would show.
    const hybrid = await signHybridAccessToken(
      { sub: 'user-1', clientId: 'client-1' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );

    await expect(
      verifyHybridAccessToken(hybrid, verify, { requirePqc: true, ...PQC_BACKEND })
    ).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('a hybrid access token passes the classical typ-enforcing verifier', async () => {
    const { signing, edPublic } = await hybridKeys();

    const hybrid = await signHybridAccessToken(
      { sub: 'user-1', clientId: 'client-1' },
      signing,
      ISSUER,
      900,
      PQC_BACKEND
    );

    // End-to-end for the case that would otherwise silently break on the day an
    // operator flips HYBRID_SIGNING_ENABLED: strict `typ` enforcement ON, hybrid
    // issuance ON, classical verify path.
    await expect(
      verifyAccessToken(hybrid.token, edPublic, { issuer: ISSUER, requireTyp: true })
    ).resolves.toMatchObject({ sub: 'user-1' });
  });
});
