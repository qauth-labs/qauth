import { createPrivateKey } from 'node:crypto';

import {
  deriveMlDsaPublicKey,
  findPrivateJwkMember,
  getSignatureBackend,
  type SignatureAlgorithm,
} from '@qauth-labs/core-crypto';
import { calculateJwkThumbprint, type JWK } from 'jose';
import { describe, expect, it } from 'vitest';

import { KeyCreationRefusedError } from './key-creation-errors';
import {
  generateKeyMaterial,
  isAllowedBySigningMode,
  jwkThumbprintKid,
  RANDOM_KID_BYTES,
  SYMMETRIC_KEY_BYTES,
} from './key-generation';
import type { KeyAlgorithm } from './key-purposes';

const ED25519_ONLY: readonly SignatureAlgorithm[] = ['EdDSA'];
const HYBRID_CAPABLE: readonly SignatureAlgorithm[] = ['EdDSA', 'ML-DSA-65'];

/** RFC 7638 §3.1: the example RSA key and its SHA-256 thumbprint. */
const RFC_7638_JWK: JWK = {
  kty: 'RSA',
  n:
    '0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAt' +
    'VT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn6' +
    '4tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FD' +
    'W2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n9' +
    '1CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINH' +
    'aQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw',
  e: 'AQAB',
  alg: 'RS256',
  kid: '2011-04-29',
};
const RFC_7638_THUMBPRINT = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

/** The public members node:crypto derives from the private key, per key type. */
const PUBLIC_MEMBERS: Record<string, readonly string[]> = {
  OKP: ['kty', 'crv', 'x'],
  EC: ['kty', 'crv', 'x', 'y'],
  RSA: ['kty', 'n', 'e'],
};

function pick(jwk: Record<string, unknown>, members: readonly string[]): Record<string, unknown> {
  return Object.fromEntries(members.map((member) => [member, jwk[member]]));
}

function expectNoPrivateMember(jwk: JWK): void {
  expect(findPrivateJwkMember(jwk)).toBeUndefined();
  expect(jwk).not.toHaveProperty('priv');
}

describe('jwkThumbprintKid', () => {
  it('matches the RFC 7638 §3.1 example', async () => {
    expect(await jwkThumbprintKid(RFC_7638_JWK)).toBe(RFC_7638_THUMBPRINT);
  });

  it('ignores the optional members kid, alg and use', async () => {
    const bare: JWK = { kty: RFC_7638_JWK.kty, n: RFC_7638_JWK.n, e: RFC_7638_JWK.e };
    expect(await jwkThumbprintKid(bare)).toBe(RFC_7638_THUMBPRINT);
    expect(await jwkThumbprintKid({ ...bare, use: 'sig', kid: 'other' })).toBe(RFC_7638_THUMBPRINT);
  });
});

describe('generateKeyMaterial', () => {
  describe.each([
    ['EdDSA', 'OKP', 'sig'],
    ['RS256', 'RSA', 'sig'],
    ['ES256', 'EC', 'sig'],
    ['ECDH-ES', 'EC', 'enc'],
  ] as const)('%s', (algorithm, kty, use) => {
    it('returns the private key as PKCS#8 DER whose public half is the published JWK', async () => {
      const key = await generateKeyMaterial(algorithm, {
        enabledSignatureAlgorithms: ED25519_ONLY,
      });
      const publicJwk = key.publicJwk as JWK;

      // A private JWK carries the public members too; take them from the
      // stored material and compare.
      const privateKey = createPrivateKey({ key: key.material, format: 'der', type: 'pkcs8' });
      const derived = privateKey.export({ format: 'jwk' });
      expect(pick({ ...publicJwk }, PUBLIC_MEMBERS[kty])).toEqual(
        pick({ ...derived }, PUBLIC_MEMBERS[kty])
      );
      expect(publicJwk.kty).toBe(kty);
      if (kty === 'EC') expect(publicJwk.crv).toBe('P-256');
    });

    it('uses the RFC 7638 thumbprint as kid, on the JWK too', async () => {
      const key = await generateKeyMaterial(algorithm, {
        enabledSignatureAlgorithms: ED25519_ONLY,
      });
      const publicJwk = key.publicJwk as JWK;

      expect(key.kid).toBe(await calculateJwkThumbprint(publicJwk, 'sha256'));
      expect(key.kid).toMatch(/^[A-Za-z0-9_-]{43}$/);
      expect(publicJwk.kid).toBe(key.kid);
    });

    it('publishes a fully specified JWK with no private member', async () => {
      const key = await generateKeyMaterial(algorithm, {
        enabledSignatureAlgorithms: ED25519_ONLY,
      });
      const publicJwk = key.publicJwk as JWK;

      expect(publicJwk.alg).toBe(algorithm);
      expect(publicJwk.use).toBe(use);
      expectNoPrivateMember(publicJwk);
    });

    it('generates a different key each time', async () => {
      const options = { enabledSignatureAlgorithms: ED25519_ONLY };
      const [first, second] = await Promise.all([
        generateKeyMaterial(algorithm, options),
        generateKeyMaterial(algorithm, options),
      ]);
      expect(first.kid).not.toBe(second.kid);
      expect(first.material.equals(second.material)).toBe(false);
    });
  });

  describe('ML-DSA-65', () => {
    it('returns the 32-byte seed and an AKP JWK of the public key it expands to', async () => {
      const key = await generateKeyMaterial('ML-DSA-65', {
        enabledSignatureAlgorithms: HYBRID_CAPABLE,
      });
      const publicJwk = key.publicJwk as JWK;
      expect(key.material).toHaveLength(32);

      const backend = getSignatureBackend('ML-DSA-65', HYBRID_CAPABLE);
      const privateKey = backend.importKey(key.material.toString('base64url'), 'private');
      const derived = deriveMlDsaPublicKey(privateKey);
      privateKey.destroy();

      expect(publicJwk).toEqual({
        kty: 'AKP',
        pub: Buffer.from(derived.material()).toString('base64url'),
        use: 'sig',
        alg: 'ML-DSA-65',
        kid: key.kid,
      });
      expectNoPrivateMember(publicJwk);
    });

    it('uses the RFC 7638 thumbprint of the AKP key as kid', async () => {
      const key = await generateKeyMaterial('ML-DSA-65', {
        enabledSignatureAlgorithms: HYBRID_CAPABLE,
      });
      expect(key.kid).toBe(await calculateJwkThumbprint(key.publicJwk as JWK, 'sha256'));
    });
  });

  describe.each(['HS256', 'A256GCM'] as const)('%s', (algorithm) => {
    it('returns 32 random bytes, a random kid and no public half', async () => {
      const options = { enabledSignatureAlgorithms: ED25519_ONLY };
      const first = await generateKeyMaterial(algorithm, options);
      const second = await generateKeyMaterial(algorithm, options);

      expect(first.material).toHaveLength(SYMMETRIC_KEY_BYTES);
      expect(first.publicJwk).toBeUndefined();
      expect(Buffer.from(first.kid, 'base64url')).toHaveLength(RANDOM_KID_BYTES);
      expect(first.kid).toMatch(/^[A-Za-z0-9_-]{22}$/);
      expect(first.kid).not.toBe(second.kid);
      expect(first.material.equals(second.material)).toBe(false);
    });
  });

  it('refuses ML-DSA-65 when SIGNING_ALGORITHM_MODE is ed25519', async () => {
    const attempt = generateKeyMaterial('ML-DSA-65', { enabledSignatureAlgorithms: ED25519_ONLY });

    await expect(attempt).rejects.toBeInstanceOf(KeyCreationRefusedError);
    await expect(attempt).rejects.toMatchObject({ reason: 'ALGORITHM_NOT_ENABLED' });
  });

  it('refuses EdDSA when the mode enables no signature algorithm', async () => {
    await expect(
      generateKeyMaterial('EdDSA', { enabledSignatureAlgorithms: [] })
    ).rejects.toMatchObject({ code: 'KEY_CREATION_REFUSED', reason: 'ALGORITHM_NOT_ENABLED' });
  });
});

describe('isAllowedBySigningMode', () => {
  it.each([
    ['EdDSA', ED25519_ONLY, true],
    ['ML-DSA-65', ED25519_ONLY, false],
    ['ML-DSA-65', HYBRID_CAPABLE, true],
    ['EdDSA', [], false],
    // The mode does not name these, so it neither allows nor refuses them.
    ['RS256', ED25519_ONLY, true],
    ['ES256', ED25519_ONLY, true],
    ['ECDH-ES', [], true],
    ['HS256', [], true],
    ['A256GCM', [], true],
  ] as const)('%s with %j → %s', (algorithm, enabled, allowed) => {
    expect(isAllowedBySigningMode(algorithm as KeyAlgorithm, enabled)).toBe(allowed);
  });
});
