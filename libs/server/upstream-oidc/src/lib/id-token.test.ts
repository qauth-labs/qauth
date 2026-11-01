import { createHmac } from 'node:crypto';

import { exportJWK, generateKeyPair, type JWK, SignJWT } from 'jose';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import { type IdTokenExpectations, type IdTokenKeys, validateIdToken } from './id-token';
import { verificationCandidates } from './jwks';

/**
 * ID token validation (#601, OpenID Connect Core 1.0 §3.1.3.7): every check
 * the acceptance criteria name refuses on its own, with everything else
 * right.
 */

const ISSUER = 'https://idp.example.com';
const CLIENT_ID = 'qauth-client';
const NONCE = 'n'.repeat(43);
const EXPECTED: IdTokenExpectations = {
  issuer: ISSUER,
  clientId: CLIENT_ID,
  nonce: NONCE,
  algorithms: ['RS256', 'ES256'],
};

let keyPair: Awaited<ReturnType<typeof generateKeyPair>>;
let publicJwk: JWK;
let otherKeyPair: Awaited<ReturnType<typeof generateKeyPair>>;

beforeAll(async () => {
  keyPair = await generateKeyPair('ES256', { extractable: true });
  publicJwk = { ...(await exportJWK(keyPair.publicKey)), kid: 'k1', alg: 'ES256', use: 'sig' };
  otherKeyPair = await generateKeyPair('ES256', { extractable: true });
});

afterEach(() => {
  vi.useRealTimers();
});

function claims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  const now = Math.floor(Date.now() / 1000);
  const all: Record<string, unknown> = {
    iss: ISSUER,
    sub: 'user-1',
    aud: CLIENT_ID,
    iat: now,
    exp: now + 300,
    nonce: NONCE,
    ...overrides,
  };
  for (const [name, value] of Object.entries(all)) if (value === undefined) delete all[name];
  return all;
}

function sign(
  payload: Record<string, unknown>,
  header: Record<string, unknown> = {},
  key = keyPair.privateKey
): Promise<string> {
  return new SignJWT(payload).setProtectedHeader({ alg: 'ES256', kid: 'k1', ...header }).sign(key);
}

/** The provider's key set, as the JWKS cache would select from it. */
const keys: IdTokenKeys = async (algorithm, kid) =>
  verificationCandidates([publicJwk], algorithm, kid);

const base64url = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');

describe('validateIdToken', () => {
  it('returns the claims of a token that passes every check', async () => {
    const token = await sign(claims({ email: 'ada@example.com' }));
    await expect(validateIdToken(token, EXPECTED, keys)).resolves.toMatchObject({
      iss: ISSUER,
      sub: 'user-1',
      email: 'ada@example.com',
    });
  });

  it.each([
    ['a wrong iss', { iss: 'https://evil.example.com' }],
    ['an iss with a trailing slash', { iss: `${ISSUER}/` }],
    ['no iss', { iss: undefined }],
    ['a wrong aud', { aud: 'another-client' }],
    ['no aud', { aud: undefined }],
    ['a wrong nonce', { nonce: 'm'.repeat(43) }],
    ['no nonce', { nonce: undefined }],
    ['an expired token', { exp: Math.floor(Date.now() / 1000) - 120 }],
    ['no exp', { exp: undefined }],
    ['no iat', { iat: undefined }],
    ['an iat in the future', { iat: Math.floor(Date.now() / 1000) + 600 }],
    ['an iat too old', { iat: Math.floor(Date.now() / 1000) - 3600 }],
    ['an nbf in the future', { nbf: Math.floor(Date.now() / 1000) + 600 }],
    ['more audiences and no azp', { aud: [CLIENT_ID, 'other'] }],
    ['an azp that is another client', { azp: 'other' }],
    ['no sub', { sub: undefined }],
    ['an empty sub', { sub: '' }],
    ['a sub longer than 255', { sub: 'x'.repeat(256) }],
    ['a sub with a control character', { sub: 'user\u00001' }],
    ['a sub that is not a string', { sub: 42 }],
  ])('refuses %s', async (_name, overrides) => {
    const token = await sign(claims(overrides));
    await expect(validateIdToken(token, EXPECTED, keys)).rejects.toMatchObject({
      name: 'UpstreamOidcError',
      reason: 'invalid_response',
    });
  });

  it('takes more audiences when azp is the client id', async () => {
    const token = await sign(claims({ aud: [CLIENT_ID, 'other'], azp: CLIENT_ID }));
    await expect(validateIdToken(token, EXPECTED, keys)).resolves.toMatchObject({ azp: CLIENT_ID });
  });

  it('takes a token issued within the clock tolerance', async () => {
    const token = await sign(claims({ iat: Math.floor(Date.now() / 1000) + 10 }));
    await expect(validateIdToken(token, EXPECTED, keys)).resolves.toBeDefined();
  });

  it('refuses a token that expired while it travelled', async () => {
    const token = await sign(claims());
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(Date.now() + 400_000);
    await expect(validateIdToken(token, EXPECTED, keys)).rejects.toThrow(/exp/);
  });

  it('refuses alg none, without looking a key up', async () => {
    const lookup = vi.fn<IdTokenKeys>(keys);
    const unsigned = `${base64url({ alg: 'none' })}.${base64url(claims())}.`;
    await expect(validateIdToken(unsigned, EXPECTED, lookup)).rejects.toThrow(/algorithm/);
    expect(lookup).not.toHaveBeenCalled();
  });

  it('refuses an HS256 token MACed with the client secret, without looking a key up', async () => {
    const lookup = vi.fn<IdTokenKeys>(keys);
    const input = `${base64url({ alg: 'HS256', kid: 'k1' })}.${base64url(claims())}`;
    const mac = createHmac('sha256', 'the-client-secret').update(input).digest('base64url');
    await expect(validateIdToken(`${input}.${mac}`, EXPECTED, lookup)).rejects.toThrow(/algorithm/);
    expect(lookup).not.toHaveBeenCalled();
    // HS256 is not even a value the expectations can hold.
    await expect(
      validateIdToken(
        `${input}.${mac}`,
        { ...EXPECTED, algorithms: ['HS256' as never] },
        async () => [{ kty: 'oct', k: Buffer.from('the-client-secret').toString('base64url') }]
      )
    ).rejects.toThrow();
  });

  it.each(['none', 'HS256', 'HS384', 'HS512'])(
    'refuses %s even when a caller lists it, before any key lookup',
    async (alg) => {
      const lookup = vi.fn<IdTokenKeys>(async () => [publicJwk]);
      const header = { alg, kid: 'k1' };
      const token = `${base64url(header)}.${base64url(claims())}.${alg === 'none' ? '' : 'c2ln'}`;
      await expect(
        validateIdToken(token, { ...EXPECTED, algorithms: [alg as never, 'ES256'] }, lookup)
      ).rejects.toThrow(/algorithm/);
      expect(lookup).not.toHaveBeenCalled();
    }
  );

  it('refuses an algorithm the provider key set has keys for but the config does not allow', async () => {
    const token = await sign(claims());
    await expect(
      validateIdToken(token, { ...EXPECTED, algorithms: ['RS256'] }, keys)
    ).rejects.toThrow(/algorithm/);
  });

  it('refuses a token signed by a key the provider does not publish', async () => {
    const token = await sign(claims(), {}, otherKeyPair.privateKey);
    await expect(validateIdToken(token, EXPECTED, keys)).rejects.toThrow(/signature/);
  });

  it('refuses a token whose kid names no published key', async () => {
    const token = await sign(claims(), { kid: 'unknown' });
    await expect(validateIdToken(token, EXPECTED, keys)).rejects.toThrow(/no key/);
  });

  it('tries each fitting key when the token names no kid', async () => {
    const other = { ...(await exportJWK(otherKeyPair.publicKey)), kid: 'k0', alg: 'ES256' };
    const token = await new SignJWT(claims())
      .setProtectedHeader({ alg: 'ES256' })
      .sign(keyPair.privateKey);
    await expect(
      validateIdToken(token, EXPECTED, async (algorithm, kid) =>
        verificationCandidates([other as JWK, publicJwk], algorithm, kid)
      )
    ).resolves.toMatchObject({ sub: 'user-1' });
  });

  it('refuses a token with a tampered payload', async () => {
    const token = await sign(claims());
    const [header, , signature] = token.split('.');
    const forged = `${header}.${base64url(claims({ sub: 'admin' }))}.${signature}`;
    await expect(validateIdToken(forged, EXPECTED, keys)).rejects.toThrow(/signature/);
  });

  it.each([undefined, '', 'not-a-jwt', 'a.b', 'x'.repeat(17 * 1024)])(
    'refuses %j as a token',
    async (token) => {
      await expect(validateIdToken(token, EXPECTED, keys)).rejects.toMatchObject({
        reason: 'invalid_response',
      });
    }
  );
});

describe('verificationCandidates', () => {
  it('selects keys by family, curve, alg, use, key_ops and kid', () => {
    const rsa: JWK = { kty: 'RSA', n: 'n', e: 'AQAB', kid: 'r' };
    const p256: JWK = { kty: 'EC', crv: 'P-256', x: 'x', y: 'y', kid: 'e' };
    const p384: JWK = { kty: 'EC', crv: 'P-384', x: 'x', y: 'y', kid: 'e384' };
    const encryption: JWK = { ...p256, kid: 'enc', use: 'enc' };
    const wrongAlg: JWK = { ...p256, kid: 'alg', alg: 'ES384' };
    const noVerify: JWK = { ...p256, kid: 'ops', key_ops: ['encrypt'] };
    const all = [rsa, p256, p384, encryption, wrongAlg, noVerify];
    expect(verificationCandidates(all, 'ES256', undefined)).toEqual([p256]);
    expect(verificationCandidates(all, 'RS256', undefined)).toEqual([rsa]);
    expect(verificationCandidates(all, 'PS256', 'r')).toEqual([rsa]);
    expect(verificationCandidates(all, 'ES384', undefined)).toEqual([p384]);
    expect(verificationCandidates(all, 'ES256', 'r')).toEqual([]);
    expect(verificationCandidates(all, 'EdDSA', undefined)).toEqual([]);
  });
});
