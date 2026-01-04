import { JWTExpiredError, JWTInvalidError } from '@qauth/shared-errors';
import { describe, expect, it } from 'vitest';

import { signAccessToken, verifyAccessToken } from './jwt-service';
import { generateEdDSAKeyPair, importPrivateKey, importPublicKey } from './key-management';

describe('signAccessToken', () => {
  it('should sign a token with valid payload', async () => {
    const { privateKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    expect(token).toBeDefined();
    expect(typeof token).toBe('string');
    // JWT tokens have three parts separated by dots
    expect(token.split('.').length).toBe(3);
  });

  it('should include all claims in the token', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-456',
      email: 'test@example.com',
      email_verified: false,
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.email).toBe(payload.email);
    expect(decoded.email_verified).toBe(payload.email_verified);
    expect(decoded.iss).toBe('https://auth.example.com');
    expect(decoded.iat).toBeDefined();
    expect(decoded.exp).toBeDefined();
  });

  it('should set expiration time correctly', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const expiresIn = 3600; // 1 hour
    const payload = {
      sub: 'user-789',
      email: 'expire@example.com',
      email_verified: true,
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', expiresIn);

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.exp).toBeDefined();
    expect(decoded.iat).toBeDefined();

    if (decoded.iat && decoded.exp) {
      const actualExpiration = decoded.exp - decoded.iat;
      // Allow 1 second tolerance
      expect(actualExpiration).toBeGreaterThanOrEqual(expiresIn - 1);
      expect(actualExpiration).toBeLessThanOrEqual(expiresIn + 1);
    }
  });
});

describe('verifyAccessToken', () => {
  it('should verify a valid token', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.email).toBe(payload.email);
    expect(decoded.email_verified).toBe(payload.email_verified);
  });

  it('should throw JWTExpiredError for expired tokens', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
    };

    // Sign with very short expiration (1 second)
    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 1);

    // Wait for token to expire
    await new Promise((resolve) => setTimeout(resolve, 1100));

    await expect(verifyAccessToken(token, publicKey)).rejects.toThrow(JWTExpiredError);
  }, 10000);

  it('should throw JWTInvalidError for invalid token format', async () => {
    const { publicKey } = await generateEdDSAKeyPair();
    const invalidToken = 'invalid.token.format';

    await expect(verifyAccessToken(invalidToken, publicKey)).rejects.toThrow(JWTInvalidError);
  });

  it('should throw JWTInvalidError for token signed with different key', async () => {
    const { privateKey: privateKey1 } = await generateEdDSAKeyPair();
    const { publicKey: publicKey2 } = await generateEdDSAKeyPair();

    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
    };

    const token = await signAccessToken(payload, privateKey1, 'https://auth.example.com', 900);

    // Try to verify with different public key
    await expect(verifyAccessToken(token, publicKey2)).rejects.toThrow(JWTInvalidError);
  });

  it('should work with imported keys', async () => {
    const { privateKey: originalPrivateKey, publicKey: originalPublicKey } =
      await generateEdDSAKeyPair(true);
    const { exportPKCS8, exportSPKI } = await import('jose');

    const privateKeyPEM = await exportPKCS8(originalPrivateKey);
    const publicKeyPEM = await exportSPKI(originalPublicKey);

    const importedPrivateKey = await importPrivateKey(privateKeyPEM);
    const importedPublicKey = await importPublicKey(publicKeyPEM);

    const payload = {
      sub: 'user-imported',
      email: 'imported@example.com',
      email_verified: true,
    };

    const token = await signAccessToken(
      payload,
      importedPrivateKey,
      'https://auth.example.com',
      900
    );

    const decoded = await verifyAccessToken(token, importedPublicKey);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.email).toBe(payload.email);
  });
});
