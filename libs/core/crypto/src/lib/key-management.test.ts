import { exportPKCS8, exportSPKI } from 'jose';
import { describe, expect, it } from 'vitest';

import {
  generateSigningKeyPair,
  importPrivateSigningKey,
  importPublicSigningKey,
} from './key-management';

describe('generateSigningKeyPair (EdDSA)', () => {
  it('generates a public/private key pair', async () => {
    const pair = await generateSigningKeyPair('EdDSA');
    expect(pair).toHaveProperty('privateKey');
    expect(pair).toHaveProperty('publicKey');
  });

  it('generates a distinct pair on each call', async () => {
    const a = await generateSigningKeyPair('EdDSA');
    const b = await generateSigningKeyPair('EdDSA');
    expect(a.privateKey).not.toBe(b.privateKey);
    expect(a.publicKey).not.toBe(b.publicKey);
  });

  it('generates a non-extractable private key by default', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA');
    expect(privateKey.extractable).toBe(false);
  });

  it('honours extractable=true so the key can be exported', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
    expect(privateKey.extractable).toBe(true);
    await expect(exportPKCS8(privateKey)).resolves.toContain('BEGIN PRIVATE KEY');
  });
});

describe('importPrivateSigningKey / importPublicSigningKey (EdDSA)', () => {
  it('round-trips an exported PEM key pair', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA', { extractable: true });
    const privatePem = await exportPKCS8(privateKey);
    const publicPem = await exportSPKI(publicKey);

    const importedPrivate = await importPrivateSigningKey(privatePem, 'EdDSA');
    const importedPublic = await importPublicSigningKey(publicPem, 'EdDSA');

    expect(importedPrivate).toBeDefined();
    expect(importedPublic).toBeDefined();
  });

  it('rejects a malformed private key PEM', async () => {
    await expect(importPrivateSigningKey('not-a-pem', 'EdDSA')).rejects.toThrow();
  });

  it('rejects a malformed public key PEM', async () => {
    await expect(importPublicSigningKey('not-a-pem', 'EdDSA')).rejects.toThrow();
  });
});
