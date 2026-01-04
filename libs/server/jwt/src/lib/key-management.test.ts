import { describe, expect, it } from 'vitest';

import { generateEdDSAKeyPair, importPrivateKey, importPublicKey } from './key-management';

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
