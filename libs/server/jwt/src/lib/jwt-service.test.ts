import { JWTExpiredError, JWTInvalidError } from '@qauth-labs/shared-errors';
import { jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

import { signAccessToken, signIdToken, verifyAccessToken } from './jwt-service';
import { generateEdDSAKeyPair, importPrivateKey, importPublicKey } from './key-management';

describe('signAccessToken', () => {
  it('should sign a token with valid payload', async () => {
    const { privateKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
      clientId: 'client-123',
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
      clientId: 'client-456',
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);

    const decoded = await verifyAccessToken(token, publicKey);
    expect(decoded.sub).toBe(payload.sub);
    expect(decoded.email).toBe(payload.email);
    expect(decoded.email_verified).toBe(payload.email_verified);
    expect(decoded.clientId).toBe(payload.clientId);
    expect(decoded.iss).toBe('https://auth.example.com');
    expect(decoded.iat).toBeDefined();
    expect(decoded.exp).toBeDefined();
    // Token-use marker is always stamped (token-confusion defence).
    expect(decoded.token_use).toBe('access');
  });

  it('should set expiration time correctly', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const expiresIn = 3600; // 1 hour
    const payload = {
      sub: 'user-789',
      email: 'expire@example.com',
      email_verified: true,
      clientId: 'client-789',
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

  it('emits and round-trips a nested RFC 8693 act claim when provided', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-deleg',
      clientId: 'agent-client',
      act: { sub: 'agent-client', act: { sub: 'prior-agent' } },
    };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);
    const decoded = await verifyAccessToken(token, publicKey);

    expect(decoded.sub).toBe('user-deleg');
    expect(decoded.act).toEqual({ sub: 'agent-client', act: { sub: 'prior-agent' } });
  });

  it('omits the act claim when not provided (non-delegated token)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = { sub: 'user-plain', clientId: 'app-client' };

    const token = await signAccessToken(payload, privateKey, 'https://auth.example.com', 900);
    const decoded = await verifyAccessToken(token, publicKey);

    expect(decoded.act).toBeUndefined();
  });
});

describe('signIdToken', () => {
  it('signs an EdDSA ID token with the required OIDC claims', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const token = await signIdToken(
      {
        sub: 'user-oidc-1',
        audience: 'client-oidc-1',
        email: 'oidc@example.com',
        email_verified: true,
        name: 'Ada Lovelace',
        nonce: 'n-0S6_WzA2Mj',
      },
      privateKey,
      'https://auth.example.com',
      900
    );

    expect(token.split('.').length).toBe(3);

    const { payload, protectedHeader } = await jwtVerify(token, publicKey, {
      algorithms: ['EdDSA'],
    });
    expect(protectedHeader.alg).toBe('EdDSA');
    expect(payload.sub).toBe('user-oidc-1');
    expect(payload.aud).toBe('client-oidc-1');
    expect(payload.iss).toBe('https://auth.example.com');
    expect(payload['email']).toBe('oidc@example.com');
    expect(payload['email_verified']).toBe(true);
    expect(payload['name']).toBe('Ada Lovelace');
    expect(payload['nonce']).toBe('n-0S6_WzA2Mj');
    expect(payload.iat).toBeDefined();
    expect(payload.exp).toBeDefined();
    // Token-use marker distinguishes the ID token from an access token.
    expect(payload['token_use']).toBe('id');
  });

  it('omits nonce and name when not supplied', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const token = await signIdToken(
      { sub: 'user-oidc-2', audience: 'client-oidc-2' },
      privateKey,
      'https://auth.example.com',
      900
    );

    const { payload } = await jwtVerify(token, publicKey, { algorithms: ['EdDSA'] });
    expect(payload['nonce']).toBeUndefined();
    expect(payload['name']).toBeUndefined();
    expect(payload['email']).toBeUndefined();
    expect(payload.sub).toBe('user-oidc-2');
    expect(payload.aud).toBe('client-oidc-2');
  });

  it('is rejected as an access token by the token-confusion guard (token_use=id)', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();

    const idToken = await signIdToken(
      { sub: 'user-oidc-3', audience: 'client-oidc-3' },
      privateKey,
      'https://auth.example.com',
      900
    );

    // The ID token verifies cryptographically (same key) but carries
    // token_use='id', so a consumer asserting an access token can detect it.
    const decoded = await verifyAccessToken(idToken, publicKey);
    expect(decoded.token_use).toBe('id');
  });
});

describe('verifyAccessToken', () => {
  it('should verify a valid token', async () => {
    const { privateKey, publicKey } = await generateEdDSAKeyPair();
    const payload = {
      sub: 'user-123',
      email: 'user@example.com',
      email_verified: true,
      clientId: 'client-123',
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
      clientId: 'client-123',
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
      clientId: 'client-123',
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
      clientId: 'client-imported',
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
