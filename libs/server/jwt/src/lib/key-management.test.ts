import { generateKeyPairSync } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  derivePublicKeyPemFromPrivate,
  generateEdDSAKeyPair,
  importPrivateKey,
  importPublicKey,
  importRs256PrivateKey,
  importRs256PublicKey,
} from './key-management';

/** Generate an extractable RSA-2048 key pair as PKCS#8 / SPKI PEM strings. */
function generateRsaPem(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
  };
}

describe('generateEdDSAKeyPair', () => {
  it('should generate a key pair', async () => {
    const keyPair = await generateEdDSAKeyPair();
    expect(keyPair).toHaveProperty('privateKey');
    expect(keyPair).toHaveProperty('publicKey');
  });

  it('should generate different key pairs each time', async () => {
    const keyPair1 = await generateEdDSAKeyPair();
    const keyPair2 = await generateEdDSAKeyPair();
    expect(keyPair1.privateKey).not.toBe(keyPair2.privateKey);
    expect(keyPair1.publicKey).not.toBe(keyPair2.publicKey);
  });

  it('should generate keys that can be used for signing', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
  });
});

describe('importPrivateKey', () => {
  it('should import a valid EdDSA private key', async () => {
    // Generate a key pair first with extractable keys for testing
    const { privateKey: originalPrivateKey } = await generateEdDSAKeyPair(true);
    // Export to PEM and re-import
    const { exportPKCS8 } = await import('jose');
    const pem = await exportPKCS8(originalPrivateKey);

    const importedKey = await importPrivateKey(pem);
    expect(importedKey).toBeDefined();
  });

  it('should throw error for invalid PEM format', async () => {
    const invalidPEM = 'invalid-pem-format';
    await expect(importPrivateKey(invalidPEM)).rejects.toThrow();
  });
});

describe('importPublicKey', () => {
  it('should import a valid EdDSA public key', async () => {
    // Generate a key pair first with extractable keys for testing
    const { generateKeyPair, exportSPKI } = await import('jose');
    const { publicKey: originalPublicKey } = await generateKeyPair('EdDSA', {
      extractable: true,
    });
    // Export to PEM and re-import
    const pem = await exportSPKI(originalPublicKey);

    const importedKey = await importPublicKey(pem);
    expect(importedKey).toBeDefined();
  });

  it('should throw error for invalid PEM format', async () => {
    const invalidPEM = 'invalid-pem-format';
    await expect(importPublicKey(invalidPEM)).rejects.toThrow();
  });
});

describe('RS256 key management (#309)', () => {
  it('imports an RS256 private key from PKCS#8 PEM', async () => {
    const { privateKeyPem } = generateRsaPem();
    const key = await importRs256PrivateKey(privateKeyPem);
    expect(key).toBeDefined();
  });

  it('imports an RS256 public key from SPKI PEM', async () => {
    const { publicKeyPem } = generateRsaPem();
    const key = await importRs256PublicKey(publicKeyPem);
    expect(key).toBeDefined();
  });

  it('throws for an invalid RS256 PEM', async () => {
    await expect(importRs256PrivateKey('not-a-pem')).rejects.toThrow();
  });

  it('derives the SPKI public PEM from a private PEM (public material only)', () => {
    const { privateKeyPem, publicKeyPem } = generateRsaPem();

    const derived = derivePublicKeyPemFromPrivate(privateKeyPem);

    // A public SPKI PEM, never a private one.
    expect(derived).toContain('BEGIN PUBLIC KEY');
    expect(derived).not.toContain('PRIVATE KEY');
    // Byte-identical to the key pair's own public half.
    expect(derived.trim()).toBe(publicKeyPem.trim());
  });

  it('derives a public key importable for RS256 verification', async () => {
    const { privateKeyPem } = generateRsaPem();
    const derivedPem = derivePublicKeyPemFromPrivate(privateKeyPem);
    const key = await importRs256PublicKey(derivedPem);
    expect(key).toBeDefined();
  });
});
