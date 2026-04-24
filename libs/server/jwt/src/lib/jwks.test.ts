import { generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { exportPublicJwk } from './jwks';

describe('exportPublicJwk', () => {
  it('returns an EdDSA signing JWK with no private component', async () => {
    const { publicKey } = await generateKeyPair('EdDSA', { extractable: true });

    const jwk = await exportPublicJwk(publicKey);

    expect(jwk.use).toBe('sig');
    expect(jwk.alg).toBe('EdDSA');
    expect(jwk['kty']).toBe('OKP');
    expect(jwk['crv']).toBe('Ed25519');
    expect(jwk['x']).toEqual(expect.any(String));
    // Critical: never leak the private key component.
    expect(jwk).not.toHaveProperty('d');
    expect(jwk.kid).toBeUndefined();
  });

  it('attaches `kid` when provided so verifiers can select a key', async () => {
    const { publicKey } = await generateKeyPair('EdDSA', { extractable: true });

    const jwk = await exportPublicJwk(publicKey, 'primary-2025');

    expect(jwk.kid).toBe('primary-2025');
  });

  it('omits `kid` for empty strings', async () => {
    const { publicKey } = await generateKeyPair('EdDSA', { extractable: true });

    const jwk = await exportPublicJwk(publicKey, '');

    expect(jwk).not.toHaveProperty('kid');
  });

  it('produces a JWK that verifies tokens signed by the matching private key', async () => {
    const { privateKey, publicKey } = await generateKeyPair('EdDSA', { extractable: true });

    const token = await new SignJWT({ scope: 'openid' })
      .setProtectedHeader({ alg: 'EdDSA' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer('https://auth.example.test')
      .setAudience('test-client')
      .setSubject('user-1')
      .sign(privateKey);

    const jwk = await exportPublicJwk(publicKey, 'test-kid');
    const reimported = await importJWK(jwk, 'EdDSA');

    const { payload } = await jwtVerify(token, reimported, {
      algorithms: ['EdDSA'],
      issuer: 'https://auth.example.test',
      audience: 'test-client',
    });

    expect(payload.sub).toBe('user-1');
    expect(payload['scope']).toBe('openid');
  });
});
