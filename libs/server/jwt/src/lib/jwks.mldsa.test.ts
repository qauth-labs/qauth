import { deriveMlDsaPublicKey, getSignatureBackend } from '@qauth-labs/core-crypto';
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
