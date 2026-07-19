import {
  deriveMlDsaPublicKey,
  getSignatureBackend,
  PQC_AKP_PUBLIC_JWK_MEMBERS,
} from '@qauth-labs/core-crypto';
import { describe, expect, it } from 'vitest';

import { exportMlDsaPublicJwk } from './jwks';

const noble = getSignatureBackend('ML-DSA-65', ['ML-DSA-65']);

describe('exportMlDsaPublicJwk (#246 AKP JWK)', () => {
  it('emits an AKP JWK with the raw public key and NO private material', () => {
    const { privateKey } = noble.generateKeyPair({ extractable: true });
    const publicKey = deriveMlDsaPublicKey(privateKey);
    const jwk = exportMlDsaPublicJwk(publicKey, 'k1-mldsa');

    expect(jwk.kty).toBe('AKP');
    expect(jwk.alg).toBe('ML-DSA-65');
    expect(jwk.use).toBe('sig');
    expect(jwk.kid).toBe('k1-mldsa');
    // pub is the base64url raw 1952-byte public key.
    expect(Buffer.from(jwk.pub, 'base64url')).toHaveLength(1952);
    expect(Buffer.from(jwk.pub, 'base64url').equals(Buffer.from(publicKey.material()))).toBe(true);

    // NEVER leaks private key material.
    const seedHex = Buffer.from(privateKey.seed()).toString('hex');
    expect(JSON.stringify(jwk)).not.toContain(seedHex);
    expect('priv' in jwk).toBe(false);
    expect('d' in jwk).toBe(false);
  });

  it('omits kid when not provided', () => {
    const { privateKey } = noble.generateKeyPair({ extractable: true });
    const jwk = exportMlDsaPublicJwk(deriveMlDsaPublicKey(privateKey));
    expect('kid' in jwk).toBe(false);
  });

  it('rejects a private key or a non-ML-DSA key', () => {
    const { privateKey } = noble.generateKeyPair({ extractable: true });
    expect(() => exportMlDsaPublicJwk(privateKey)).toThrow(/public ML-DSA-65/);
  });

  // #274: the emitted AKP JWK must match the RFC 9964 member set EXACTLY.
  // RFC 9964 makes kty/alg/pub REQUIRED and forbids `priv` in a public key;
  // use/kid are the ordinary RFC 7517 members. A new member appearing here is
  // an interop-visible wire change and must be a deliberate edit.
  describe('RFC 9964 AKP member set', () => {
    it('emits exactly {kty, pub, use, alg, kid} and nothing else', () => {
      const { privateKey } = noble.generateKeyPair({ extractable: true });
      const jwk = exportMlDsaPublicJwk(deriveMlDsaPublicKey(privateKey), 'k1-mldsa');
      expect(Object.keys(jwk).sort()).toEqual([...PQC_AKP_PUBLIC_JWK_MEMBERS].sort());
    });

    it('emits exactly {kty, pub, use, alg} when no kid is configured', () => {
      const { privateKey } = noble.generateKeyPair({ extractable: true });
      const jwk = exportMlDsaPublicJwk(deriveMlDsaPublicKey(privateKey));
      const expected = PQC_AKP_PUBLIC_JWK_MEMBERS.filter((m) => m !== 'kid');
      expect(Object.keys(jwk).sort()).toEqual([...expected].sort());
    });

    it('never emits any RFC 9964 or classical private-key member', () => {
      const { privateKey } = noble.generateKeyPair({ extractable: true });
      const jwk = exportMlDsaPublicJwk(deriveMlDsaPublicKey(privateKey), 'k1-mldsa');
      // `priv` is the RFC 9964 AKP private member (the 32-byte seed); d/k/p/q
      // are the classical JWK private members.
      for (const forbidden of ['priv', 'd', 'k', 'p', 'q', 'dp', 'dq', 'qi', 'seed']) {
        expect(Object.keys(jwk)).not.toContain(forbidden);
      }
    });

    it('matches the RFC 9964 example JWK shape (kty AKP, base64url pub, alg names the parameter set)', () => {
      const { privateKey } = noble.generateKeyPair({ extractable: true });
      const jwk = exportMlDsaPublicJwk(deriveMlDsaPublicKey(privateKey), 'k1-mldsa');
      expect(jwk.kty).toBe('AKP');
      // RFC 9864 fully-specified: `alg` alone determines the operation, so
      // there is no companion `crv`-style parameter member.
      expect(jwk.alg).toBe('ML-DSA-65');
      expect(Object.keys(jwk)).not.toContain('crv');
      // base64url, unpadded, no standard-base64 characters.
      expect(jwk.pub).toMatch(/^[A-Za-z0-9_-]+$/);
    });
  });

  it('the published AKP key verifies a signature made with its private half', () => {
    // End-to-end: a verifier reconstructing the key from the JWK can validate.
    const { privateKey } = noble.generateKeyPair({ extractable: true });
    const publicKey = deriveMlDsaPublicKey(privateKey);
    const jwk = exportMlDsaPublicJwk(publicKey);
    const reconstructed = noble.importKey(jwk.pub, 'public');
    const message = new TextEncoder().encode('jwks round-trip');
    const sig = noble.sign(privateKey, message);
    expect(() => noble.verify(reconstructed, message, sig)).not.toThrow();
  });
});
