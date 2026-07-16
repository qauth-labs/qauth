import { describe, expect, it } from 'vitest';

import { CryptoVerificationError } from './errors';
import { generateSigningKeyPair } from './key-management';
import { sign, verify } from './signing';

const ISSUER = 'https://auth.example.com';

describe('sign / verify (EdDSA)', () => {
  it('signs a compact JWT and round-trips the claims through verify', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');

    const token = await sign({ sub: 'user-1', role: 'admin' }, privateKey, 'EdDSA', {
      issuer: ISSUER,
      expiresIn: 900,
      audience: 'client-1',
    });

    // Compact JWS has three dot-separated segments.
    expect(token.split('.')).toHaveLength(3);

    const claims = await verify(token, publicKey, { algorithms: ['EdDSA'] });
    expect(claims['sub']).toBe('user-1');
    expect(claims['role']).toBe('admin');
    expect(claims['iss']).toBe(ISSUER);
    expect(claims['aud']).toBe('client-1');
    expect(claims['iat']).toBeTypeOf('number');
    expect(claims['exp']).toBeTypeOf('number');
  });

  it('stamps exp as iat + expiresIn', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');
    const expiresIn = 3600;

    const token = await sign({ sub: 'user-1' }, privateKey, 'EdDSA', {
      issuer: ISSUER,
      expiresIn,
      audience: 'client-1',
    });

    const claims = await verify(token, publicKey, { algorithms: ['EdDSA'] });
    const iat = claims['iat'] as number;
    const exp = claims['exp'] as number;
    expect(exp - iat).toBe(expiresIn);
  });

  it('enforces the issuer when supplied (rejects a mismatched issuer)', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');
    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', {
      issuer: 'https://attacker.example.com',
      expiresIn: 900,
      audience: 'client-1',
    });

    await expect(
      verify(token, publicKey, { algorithms: ['EdDSA'], issuer: ISSUER })
    ).rejects.toBeInstanceOf(CryptoVerificationError);
  });

  it('enforces the audience when supplied (rejects a mismatched audience)', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');
    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', {
      issuer: ISSUER,
      expiresIn: 900,
      audience: 'client-1',
    });

    await expect(
      verify(token, publicKey, { algorithms: ['EdDSA'], audience: 'other-client' })
    ).rejects.toMatchObject({
      name: 'CryptoVerificationError',
      reason: 'invalid',
    });
  });

  it('throws CryptoVerificationError(reason="expired") for an expired token', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');
    const expiresIn = 900;
    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', {
      issuer: ISSUER,
      expiresIn,
      audience: 'client-1',
    });

    // Evaluate temporal claims one second past expiry — deterministic, no sleep.
    const pastExpiry = new Date(Date.now() + (expiresIn + 1) * 1000);

    await expect(
      verify(token, publicKey, { algorithms: ['EdDSA'], currentDate: pastExpiry })
    ).rejects.toMatchObject({
      name: 'CryptoVerificationError',
      reason: 'expired',
    });
  });

  it('accepts a just-expired token within the clock tolerance', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');
    const expiresIn = 900;
    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', {
      issuer: ISSUER,
      expiresIn,
      audience: 'client-1',
    });

    const pastExpiry = new Date(Date.now() + (expiresIn + 1) * 1000);

    await expect(
      verify(token, publicKey, {
        algorithms: ['EdDSA'],
        currentDate: pastExpiry,
        clockTolerance: 5,
      })
    ).resolves.toMatchObject({ sub: 'u' });
  });

  it('throws CryptoVerificationError(reason="invalid") with backend detail for a bad signature', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA');
    const { publicKey: otherKey } = await generateSigningKeyPair('EdDSA');
    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', {
      issuer: ISSUER,
      expiresIn: 900,
      audience: 'client-1',
    });

    // Verified with a key the token was NOT signed with.
    await expect(verify(token, otherKey, { algorithms: ['EdDSA'] })).rejects.toMatchObject({
      name: 'CryptoVerificationError',
      reason: 'invalid',
      detail: expect.any(String),
    });
  });

  it('throws CryptoVerificationError(reason="invalid") for a structurally malformed token', async () => {
    const { publicKey } = await generateSigningKeyPair('EdDSA');

    const error = await verify('not.a.jwt', publicKey, { algorithms: ['EdDSA'] }).catch(
      (e: unknown) => e
    );
    expect(error).toBeInstanceOf(CryptoVerificationError);
    expect((error as CryptoVerificationError).reason).toBe('invalid');
  });
});
