import { generateKeyPair, importJWK, jwtVerify, SignJWT } from 'jose';
import { describe, expect, it } from 'vitest';

import { exportPublicJwk, exportRs256PublicJwk } from './jwks';

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

describe('exportRs256PublicJwk (#309)', () => {
  it('returns an RSA signing JWK with only public members (n, e)', async () => {
    const { publicKey } = await generateKeyPair('RS256', { extractable: true });

    const jwk = await exportRs256PublicJwk(publicKey);

    expect(jwk.kty).toBe('RSA');
    expect(jwk.use).toBe('sig');
    expect(jwk.alg).toBe('RS256');
    expect(typeof jwk.n).toBe('string');
    expect(typeof jwk.e).toBe('string');
    expect(jwk.kid).toBeUndefined();
    // Private RSA members MUST never be published (RFC 7517 §9.3).
    for (const member of ['d', 'p', 'q', 'dp', 'dq', 'qi']) {
      expect(jwk).not.toHaveProperty(member);
    }
  });

  it('attaches `kid` when provided so it can be distinct from the EdDSA key', async () => {
    const { publicKey } = await generateKeyPair('RS256', { extractable: true });

    const jwk = await exportRs256PublicJwk(publicKey, 'rsa-2025');

    expect(jwk.kid).toBe('rsa-2025');
  });

  it('omits `kid` for empty strings', async () => {
    const { publicKey } = await generateKeyPair('RS256', { extractable: true });

    const jwk = await exportRs256PublicJwk(publicKey, '');

    expect(jwk).not.toHaveProperty('kid');
  });

  it('fails closed when handed a private key rather than silently leaking it', async () => {
    // A misconfigured caller passing the PRIVATE key must be rejected, not
    // published — `exportJWK` on an extractable private RSA key exposes `d`/… .
    const { privateKey } = await generateKeyPair('RS256', { extractable: true });

    await expect(exportRs256PublicJwk(privateKey)).rejects.toThrow(/private RSA members/i);
  });

  it('produces a JWK that verifies tokens signed by the matching RS256 private key', async () => {
    const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });

    const token = await new SignJWT({ scope: 'openid' })
      .setProtectedHeader({ alg: 'RS256' })
      .setIssuedAt()
      .setExpirationTime('5m')
      .setIssuer('https://auth.example.test')
      .setAudience('test-client')
      .setSubject('user-rs256')
      .sign(privateKey);

    const jwk = await exportRs256PublicJwk(publicKey, 'rsa-kid');
    const reimported = await importJWK(jwk, 'RS256');

    const { payload, protectedHeader } = await jwtVerify(token, reimported, {
      algorithms: ['RS256'],
      issuer: 'https://auth.example.test',
      audience: 'test-client',
    });

    expect(protectedHeader.alg).toBe('RS256');
    expect(payload.sub).toBe('user-rs256');
    expect(payload['scope']).toBe('openid');
  });
});
