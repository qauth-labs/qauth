import { describe, expect, it } from 'vitest';

import { CryptoVerificationError } from './errors';
import { generateSigningKeyPair } from './key-management';
import { RESERVED_PROTECTED_HEADER_MEMBERS, sign, verify } from './signing';

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

describe('sign() protected-header invariant (#248 F6)', () => {
  const baseOpts = { issuer: ISSUER, expiresIn: 900, audience: 'client-1' };

  /** Decode a compact JWS protected header without verifying (test-only). */
  function decodeHeader(token: string): Record<string, unknown> {
    const [encodedHeader] = token.split('.');
    return JSON.parse(Buffer.from(encodedHeader, 'base64url').toString('utf-8')) as Record<
      string,
      unknown
    >;
  }

  it('merges non-reserved header members alongside the canonical alg', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA');

    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', {
      ...baseOpts,
      header: { kid: 'ed-1', pqc_alg: 'ML-DSA-65', pqc_kid: 'mldsa-1' },
    });

    const header = decodeHeader(token);
    expect(header['alg']).toBe('EdDSA');
    expect(header['kid']).toBe('ed-1');
    expect(header['pqc_alg']).toBe('ML-DSA-65');
    expect(header['pqc_kid']).toBe('mldsa-1');
  });

  // Each reserved member gets its own case: they defend different invariants
  // (algorithm confusion, classical-verifier compatibility, payload encoding),
  // so a regression in any one of them must fail on its own.
  for (const member of RESERVED_PROTECTED_HEADER_MEMBERS) {
    it(`throws when options.header carries the reserved member '${member}'`, async () => {
      const { privateKey } = await generateSigningKeyPair('EdDSA');

      await expect(
        sign({ sub: 'u' }, privateKey, 'EdDSA', {
          ...baseOpts,
          // A realistic hostile value per member; the rejection is by NAME, so
          // the value is irrelevant — no reserved member may be caller-set.
          header: { [member]: member === 'crit' ? ['pqc_alg'] : member === 'b64' ? false : 'none' },
        })
      ).rejects.toThrow(new RegExp(`'${member}' is reserved`));
    });
  }

  it('lists every reserved member in the rejection message (operator diagnosability)', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA');

    await expect(
      sign({ sub: 'u' }, privateKey, 'EdDSA', { ...baseOpts, header: { alg: 'none' } })
    ).rejects.toThrow(/alg, crit, b64/);
  });

  it('rejects an alg override rather than silently honouring it (algorithm confusion)', async () => {
    const { privateKey, publicKey } = await generateSigningKeyPair('EdDSA');

    // The attack this closes: a caller-supplied `alg: 'none'` reaching the
    // protected header. It must never be merged, and it must never be silently
    // dropped either — the caller has to learn it was refused.
    await expect(
      sign({ sub: 'u' }, privateKey, 'EdDSA', { ...baseOpts, header: { alg: 'none' } })
    ).rejects.toThrow(/reserved/);

    // Sanity: without the reserved member the canonical alg is what verifies.
    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', baseOpts);
    expect(decodeHeader(token)['alg']).toBe('EdDSA');
    await expect(verify(token, publicKey, { algorithms: ['EdDSA'] })).resolves.toBeDefined();
  });

  it('ignores a reserved member inherited from the prototype chain', async () => {
    const { privateKey } = await generateSigningKeyPair('EdDSA');

    // `Object.hasOwn` (not `in`) means a prototype-polluted Object.prototype
    // cannot make an innocent header spuriously fail closed.
    const header = Object.create({ alg: 'none' }) as Record<string, unknown>;
    header['kid'] = 'ed-1';

    const token = await sign({ sub: 'u' }, privateKey, 'EdDSA', { ...baseOpts, header });
    expect(decodeHeader(token)['alg']).toBe('EdDSA');
  });
});
