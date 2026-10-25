import {
  constants,
  createHmac,
  createPrivateKey,
  generateKeyPairSync,
  sign as nodeSign,
} from 'node:crypto';

import { calculateJwkThumbprint, CompactSign } from 'jose';
import { beforeEach, describe, expect, it } from 'vitest';

import {
  type FakeReplayStore,
  fakeReplayStore,
  rawJws,
  signProof,
  TEST_METHOD,
  TEST_URL,
  type TestKey,
  testKey,
} from '../testing/proofs';
import { DEFAULT_DPOP_ALGORITHMS, type DpopAlgorithm } from './algorithms';
import { DpopProofError, type DpopRejectionReason } from './dpop-error';
import { createHmacDpopNonceSource } from './nonce';
import {
  createDpopVerifier,
  dpopAccessTokenHash,
  type DpopProofCheck,
  type DpopVerifierOptions,
  MAX_DPOP_JTI_LENGTH,
  MAX_DPOP_PROOF_LENGTH,
} from './verifier';

/**
 * The shared DPoP proof verifier (RFC 9449 §4.3, issue #479). One describe
 * block per check, each with the case that fails it; the RFC's own example
 * proofs and the shared negative cases run in `vectors.test.ts`.
 */

const NOW_MS = Date.UTC(2026, 9, 25, 12, 0, 0);
const NOW = NOW_MS / 1000;

let clock: number;
let store: FakeReplayStore;
let es256: TestKey;

beforeEach(async () => {
  clock = NOW_MS;
  store = fakeReplayStore(() => clock);
  es256 ??= await testKey('ES256');
});

function verifier(options: Partial<DpopVerifierOptions> = {}) {
  return createDpopVerifier({ replayStore: store, now: () => clock, ...options });
}

function proof(parts: { header?: Record<string, unknown>; claims?: Record<string, unknown> } = {}) {
  return signProof({ key: es256, iat: NOW, ...parts });
}

function check(
  value: DpopProofCheck['proof'],
  extra: Partial<DpopProofCheck> = {}
): DpopProofCheck {
  return { proof: value, method: TEST_METHOD, url: TEST_URL, ...extra };
}

/** The refusal `promise` rejects with; fails when it resolves or rejects with anything else. */
async function refusal(promise: Promise<unknown>): Promise<DpopProofError> {
  const error = await promise.then(
    () => undefined,
    (reason: unknown) => reason
  );
  expect(error).toBeInstanceOf(DpopProofError);
  return error as DpopProofError;
}

async function expectRefused(
  promise: Promise<unknown>,
  reason: DpopRejectionReason
): Promise<DpopProofError> {
  const error = await refusal(promise);
  expect(error.reason).toBe(reason);
  return error;
}

describe('a valid proof', () => {
  it("returns the key's RFC 7638 SHA-256 thumbprint and records the proof once", async () => {
    const value = await proof({ claims: { jti: 'jti-0001' } });

    const result = await verifier().verify(check(value));

    expect(result.thumbprint).toBe(await calculateJwkThumbprint(es256.publicJwk, 'sha256'));
    expect(result.algorithm).toBe('ES256');
    expect(result.jti).toBe('jti-0001');
    expect(result.issuedAt).toBe(NOW);
    expect(result.jwk).toEqual(es256.publicJwk);
    expect(result.nextNonce).toBeUndefined();
    // Held for two windows and a second, under a hash that names neither the key nor the jti.
    expect(store.calls).toEqual([
      { key: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/), ttlMs: 121_000 },
    ]);
    expect(store.calls[0].key).not.toContain('jti-0001');
  });

  it.each(DEFAULT_DPOP_ALGORITHMS)('verifies %s, on the default allowlist', async (alg) => {
    const key = await testKey(alg);
    const value = await signProof({ key, iat: NOW });

    const result = await verifier().verify(check(value));

    expect(result.algorithm).toBe(alg);
    expect(result.thumbprint).toBe(await calculateJwkThumbprint(key.publicJwk, 'sha256'));
  });

  it('accepts RSASSA-PKCS1-v1_5 only when the endpoint allows it', async () => {
    const key = await testKey('RS256');
    const value = await signProof({ key, iat: NOW });

    await expectRefused(verifier().verify(check(value)), 'alg');
    await expect(verifier({ algorithms: ['RS256'] }).verify(check(value))).resolves.toMatchObject({
      algorithm: 'RS256',
    });
  });

  it('lists its allowlist for discovery and the challenge', () => {
    expect(verifier().algorithms).toEqual(DEFAULT_DPOP_ALGORITHMS);
    expect(verifier({ algorithms: ['ES256', 'EdDSA'] }).algorithms).toEqual(['ES256', 'EdDSA']);
  });
});

describe('the DPoP header (RFC 9449 §4.3 steps 1 and 2)', () => {
  it.each([[undefined], [''], ['   '], [[]], [['']]])(
    'refuses a request without one: %j',
    async (value) => {
      await expectRefused(verifier().verify(check(value)), 'missing-proof');
    }
  );

  it('refuses two headers, as a list or joined by a comma', async () => {
    const value = await proof();
    await expectRefused(verifier().verify(check([value, value])), 'multiple-proofs');
    await expectRefused(verifier().verify(check(`${value}, ${value}`)), 'multiple-proofs');
  });

  it('accepts one header given as a one-item list', async () => {
    await expect(verifier().verify(check([await proof()]))).resolves.toBeDefined();
  });

  it.each([
    ['not a JWT', 'not-a-jwt'],
    ['four parts', 'a.b.c.d'],
    ['an empty signature', 'a.b.'],
    ['characters outside base64url', 'a+b.c/d.e=f'],
    ['a header that is not JSON', 'bm90IGpzb24.e30.c2ln'],
  ])('refuses %s', async (_label, value) => {
    await expectRefused(verifier().verify(check(value)), 'malformed');
  });

  it(`refuses a proof longer than ${MAX_DPOP_PROOF_LENGTH} characters`, async () => {
    const value = await proof({ claims: { padding: 'x'.repeat(MAX_DPOP_PROOF_LENGTH) } });
    await expectRefused(verifier().verify(check(value)), 'malformed');
  });

  it('refuses a payload that is not a JSON object', async () => {
    const value = await new CompactSign(new TextEncoder().encode('["jti"]'))
      .setProtectedHeader({ typ: 'dpop+jwt', alg: 'ES256', jwk: es256.publicJwk })
      .sign(es256.privateKey);
    await expectRefused(verifier().verify(check(value)), 'malformed');
  });

  it('refuses a crit header, which names an extension it cannot honour', async () => {
    const value = rawJws(
      { typ: 'dpop+jwt', alg: 'ES256', jwk: es256.publicJwk, crit: ['exp'] },
      {}
    );
    await expectRefused(verifier().verify(check(value)), 'malformed');
  });
});

describe('typ (RFC 9449 §4.3 step 4, §11.5)', () => {
  it.each([undefined, 'JWT', 'jwt', 'at+jwt', 'application/dpop+jwt', 'DPOP+JWT'])(
    'refuses typ %s',
    async (typ) => {
      await expectRefused(verifier().verify(check(await proof({ header: { typ } }))), 'typ');
    }
  );
});

describe('alg (RFC 9449 §4.3 step 5, §11.6)', () => {
  it('refuses none', async () => {
    const value = rawJws(
      { typ: 'dpop+jwt', alg: 'none', jwk: es256.publicJwk },
      { jti: 'x', htm: TEST_METHOD, htu: TEST_URL, iat: NOW },
      'AA'
    );
    await expectRefused(verifier().verify(check(value)), 'alg');
  });

  it.each(['HS256', 'HS384', 'HS512'])(
    'refuses the MAC algorithm %s, correctly signed',
    async (alg) => {
      const secret = Buffer.from('a throwaway test secret for the MAC case, 32+ bytes');
      const header = { typ: 'dpop+jwt', alg, jwk: { kty: 'oct', k: secret.toString('base64url') } };
      const claims = { jti: 'x', htm: TEST_METHOD, htu: TEST_URL, iat: NOW };
      const input = rawJws(header, claims).split('.').slice(0, 2).join('.');
      const mac = createHmac(`sha${alg.slice(2)}`, secret)
        .update(input)
        .digest('base64url');
      await expectRefused(verifier().verify(check(`${input}.${mac}`)), 'alg');
    }
  );

  it('refuses an algorithm the endpoint did not allow', async () => {
    const key = await testKey('ES384');
    const value = await signProof({ key, iat: NOW });
    await expectRefused(verifier({ algorithms: ['ES256'] }).verify(check(value)), 'alg');
  });

  it.each(['ES256K', 'RSA-OAEP', 'ML-DSA-65', 'es256'])(
    'refuses the unknown or unsuitable name %s',
    async (alg) => {
      const value = rawJws({ typ: 'dpop+jwt', alg, jwk: es256.publicJwk }, {});
      await expectRefused(verifier().verify(check(value)), 'alg');
    }
  );

  it('refuses at creation an allowlist that names none, a MAC or nothing', () => {
    for (const algorithms of [['none'], ['HS256'], ['ES256', 'HS512'], []]) {
      expect(() => verifier({ algorithms: algorithms as DpopAlgorithm[] })).toThrow(TypeError);
    }
  });
});

describe('jwk (RFC 9449 §4.3 steps 6 and 7)', () => {
  it('refuses a proof without one', async () => {
    await expectRefused(
      verifier().verify(check(await proof({ header: { jwk: undefined } }))),
      'jwk'
    );
  });

  it('refuses a jwk that is not an object', async () => {
    const value = rawJws({ typ: 'dpop+jwt', alg: 'ES256', jwk: 'key' }, {});
    await expectRefused(verifier().verify(check(value)), 'jwk');
  });

  it('refuses a jwk with the private key, correctly signed', async () => {
    const value = await proof({ header: { jwk: es256.privateJwk } });
    await expectRefused(verifier().verify(check(value)), 'private-key');
  });

  it.each(['p', 'q', 'dp', 'dq', 'qi', 'oth'])(
    'refuses an RSA jwk with the private member %s',
    async (member) => {
      const key = await testKey('PS256');
      const jwk = { ...key.publicJwk, [member]: key.privateJwk[member as 'p'] ?? 'AQAB' };
      const value = await signProof({ key, iat: NOW, header: { jwk } });
      await expectRefused(verifier().verify(check(value)), 'private-key');
    }
  );

  it('refuses a symmetric key, whatever the alg says', async () => {
    const value = rawJws({ typ: 'dpop+jwt', alg: 'ES256', jwk: { kty: 'oct', k: 'c2VjcmV0' } }, {});
    await expectRefused(verifier().verify(check(value)), 'private-key');
  });

  it('refuses a key of another type or curve than alg needs', async () => {
    const ed = await testKey('EdDSA');
    const p384 = await testKey('ES384');
    await expectRefused(
      verifier().verify(check(await proof({ header: { jwk: ed.publicJwk } }))),
      'jwk'
    );
    await expectRefused(
      verifier().verify(check(await proof({ header: { jwk: p384.publicJwk } }))),
      'jwk'
    );
  });

  it('refuses a key that does not import', async () => {
    const jwk = { kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' };
    await expectRefused(verifier().verify(check(await proof({ header: { jwk } }))), 'jwk');
  });

  it('refuses an RSA key under 2048 bits', async () => {
    const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 1024 });
    const header = { typ: 'dpop+jwt', alg: 'PS256', jwk: publicKey.export({ format: 'jwk' }) };
    const input = rawJws(header, { jti: 'x', htm: TEST_METHOD, htu: TEST_URL, iat: NOW })
      .split('.')
      .slice(0, 2)
      .join('.');
    const signature = nodeSign('sha256', Buffer.from(input), {
      key: createPrivateKey(privateKey.export({ format: 'pem', type: 'pkcs8' })),
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    }).toString('base64url');
    await expectRefused(verifier().verify(check(`${input}.${signature}`)), 'jwk');
  });
});

describe('the signature (RFC 9449 §4.3 step 6)', () => {
  it('refuses a proof signed by another key than its jwk', async () => {
    const other = await testKey('ES256');
    const value = await signProof({ key: other, iat: NOW, header: { jwk: es256.publicJwk } });
    await expectRefused(verifier().verify(check(value)), 'signature');
  });

  it('refuses a proof whose payload was changed after signing', async () => {
    const [header, , signature] = (await proof()).split('.');
    const payload = Buffer.from(
      JSON.stringify({ jti: 'changed', htm: TEST_METHOD, htu: TEST_URL, iat: NOW })
    ).toString('base64url');
    await expectRefused(verifier().verify(check(`${header}.${payload}.${signature}`)), 'signature');
  });
});

describe('claims of the other JWT types a DPoP key signs (ADR-014 §4)', () => {
  it.each(['sub', 'cnf', 'events'])('refuses a proof with %s', async (claim) => {
    const value = await proof({ claims: { [claim]: claim === 'sub' ? 'agent' : {} } });
    await expectRefused(verifier().verify(check(value)), 'claims-not-allowed');
  });
});

describe('jti (RFC 9449 §4.2, §11.1)', () => {
  it.each([
    ['missing', undefined],
    ['empty', ''],
    ['a number', 42],
    [`longer than ${MAX_DPOP_JTI_LENGTH} characters`, 'j'.repeat(MAX_DPOP_JTI_LENGTH + 1)],
  ])('refuses a jti that is %s', async (_label, jti) => {
    await expectRefused(verifier().verify(check(await proof({ claims: { jti } }))), 'jti');
  });

  it(`accepts a jti of ${MAX_DPOP_JTI_LENGTH} characters`, async () => {
    const value = await proof({ claims: { jti: 'j'.repeat(MAX_DPOP_JTI_LENGTH) } });
    await expect(verifier().verify(check(value))).resolves.toBeDefined();
  });
});

describe('htm (RFC 9449 §4.3 step 8)', () => {
  it('refuses a proof for another method than the caller names', async () => {
    await expectRefused(verifier().verify(check(await proof(), { method: 'GET' })), 'htm');
  });

  it('compares the method exactly, as HTTP does', async () => {
    await expectRefused(verifier().verify(check(await proof({ claims: { htm: 'post' } }))), 'htm');
  });

  it('refuses a proof without htm', async () => {
    await expectRefused(
      verifier().verify(check(await proof({ claims: { htm: undefined } }))),
      'htm'
    );
  });
});

describe('htu (RFC 9449 §4.3 step 9)', () => {
  it.each([
    ['another path', 'https://auth.example.com/oauth/introspect'],
    ['another host', 'https://attacker.example.com/oauth/token'],
    ['another scheme', 'http://auth.example.com/oauth/token'],
    ['another port', 'https://auth.example.com:8443/oauth/token'],
    ['a trailing slash', 'https://auth.example.com/oauth/token/'],
  ])('refuses a proof for %s than the caller names', async (_label, url) => {
    await expectRefused(verifier().verify(check(await proof(), { url })), 'htu');
  });

  it('checks the URL the caller passes, not one the proof chooses', async () => {
    // A proof made for the attacker's URL fails at the endpoint it is replayed to,
    // however it is presented.
    const value = await proof({ claims: { htu: 'https://attacker.example.com/oauth/token' } });
    await expectRefused(verifier().verify(check(value)), 'htu');
  });

  it.each([
    ['missing', undefined],
    ['not a URL', 'oauth/token'],
    ['not http', 'ftp://auth.example.com/oauth/token'],
    ['with user information', 'https://user@auth.example.com/oauth/token'],
  ])('refuses an htu that is %s', async (_label, htu) => {
    await expectRefused(verifier().verify(check(await proof({ claims: { htu } }))), 'htu');
  });

  it('ignores the query and the fragment on both sides', async () => {
    const value = await proof({ claims: { htu: `${TEST_URL}?client=1#top` } });
    await expect(
      verifier().verify(check(value, { url: `${TEST_URL}?state=2` }))
    ).resolves.toBeDefined();
  });

  it('compares after RFC 3986 syntax- and scheme-based normalization', async () => {
    const value = await proof({ claims: { htu: 'HTTPS://Auth.Example.COM:443/oauth/%74oken' } });
    await expect(verifier().verify(check(value))).resolves.toBeDefined();
  });

  it('throws when the caller passes a URL it cannot check against', async () => {
    await expect(verifier().verify(check(await proof(), { url: '/oauth/token' }))).rejects.toThrow(
      TypeError
    );
  });
});

describe('iat (RFC 9449 §4.3 step 11, §11.1)', () => {
  it.each([
    ['61 seconds old', NOW - 61],
    ['61 seconds ahead', NOW + 61],
  ])('refuses a proof %s with the default 60-second window', async (_label, iat) => {
    await expectRefused(verifier().verify(check(await proof({ claims: { iat } }))), 'iat');
  });

  it.each([
    ['60 seconds old', NOW - 60],
    ['60 seconds ahead', NOW + 60],
  ])('accepts a proof %s, at the edge of the window', async (_label, iat) => {
    await expect(verifier().verify(check(await proof({ claims: { iat } })))).resolves.toBeDefined();
  });

  it('applies the window the endpoint sets', async () => {
    const value = await proof({ claims: { iat: NOW - 20 } });
    await expectRefused(verifier({ iatWindowSeconds: 10 }).verify(check(value)), 'iat');
  });

  it.each([
    ['missing', undefined],
    ['a string', String(NOW)],
  ])('refuses an iat that is %s', async (_label, iat) => {
    await expectRefused(verifier().verify(check(await proof({ claims: { iat } }))), 'iat');
  });

  it('refuses at creation a window that is not a positive whole number', () => {
    for (const iatWindowSeconds of [0, -1, 1.5, Number.NaN]) {
      expect(() => verifier({ iatWindowSeconds })).toThrow(TypeError);
    }
  });
});

describe('ath (RFC 9449 §4.3 step 12, §7)', () => {
  const TOKEN = 'eyJhbGciOiJFZERTQSJ9.access-token-for-the-ath-check.c2ln';

  it('accepts a proof whose ath is the hash of the presented token', async () => {
    const value = await proof({ claims: { ath: dpopAccessTokenHash(TOKEN) } });
    await expect(verifier().verify(check(value, { accessToken: TOKEN }))).resolves.toBeDefined();
  });

  it('refuses a proof made for another token', async () => {
    const value = await proof({ claims: { ath: dpopAccessTokenHash(`${TOKEN}-other`) } });
    await expectRefused(verifier().verify(check(value, { accessToken: TOKEN })), 'ath');
  });

  it('refuses a proof without ath when a token is presented', async () => {
    await expectRefused(verifier().verify(check(await proof(), { accessToken: TOKEN })), 'ath');
  });

  it('computes ath as base64url SHA-256 of the token (RFC 9449 Figure 14)', () => {
    expect(dpopAccessTokenHash('Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU')).toBe(
      'fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo'
    );
  });
});

describe('the key a token is bound to (RFC 9449 §4.3 step 12, §6)', () => {
  it('accepts the bound key and refuses another', async () => {
    const thumbprint = await calculateJwkThumbprint(es256.publicJwk, 'sha256');
    const other = await calculateJwkThumbprint((await testKey('ES256')).publicJwk, 'sha256');

    await expect(
      verifier().verify(check(await proof(), { expectedThumbprint: thumbprint }))
    ).resolves.toBeDefined();
    await expectRefused(
      verifier().verify(check(await proof(), { expectedThumbprint: other })),
      'key-mismatch'
    );
  });
});

describe('the server-provided nonce (RFC 9449 §8, §9, §11.3)', () => {
  const nonces = () => createHmacDpopNonceSource({ secret: Buffer.alloc(32, 7), now: () => clock });

  it('answers use_dpop_nonce with a fresh nonce when a required nonce is missing', async () => {
    const source = nonces();
    const error = await expectRefused(
      verifier({ nonces: source }).verify(check(await proof(), { requireNonce: true })),
      'nonce-required'
    );

    expect(error.error).toBe('use_dpop_nonce');
    expect(error.nonce).toBe(source.current());
    expect(store.calls).toEqual([]);
  });

  it('answers use_dpop_nonce when the nonce is not one the server provided', async () => {
    const source = nonces();
    const error = await expectRefused(
      verifier({ nonces: source }).verify(
        check(await proof({ claims: { nonce: 'eyJ7S_zG.eyJH0-Z.HX4w-7v' } }), {
          requireNonce: true,
        })
      ),
      'nonce-invalid'
    );
    expect(error.error).toBe('use_dpop_nonce');
    expect(error.nonce).toBe(source.current());
  });

  it('accepts the retry that carries the nonce, and hands out the next one', async () => {
    const source = nonces();
    const nonce = source.current();

    const result = await verifier({ nonces: source }).verify(
      check(await proof({ claims: { nonce } }), { requireNonce: true })
    );

    expect(result.nextNonce).toBe(nonce);
  });

  it('ignores a nonce when the endpoint does not require one', async () => {
    const value = await proof({ claims: { nonce: 'from-another-server' } });
    await expect(verifier({ nonces: nonces() }).verify(check(value))).resolves.toBeDefined();
  });

  it('hands out a nonce for a response without a proof', async () => {
    const source = nonces();
    await expect(verifier({ nonces: source }).nonce()).resolves.toBe(source.current());
    await expect(verifier().nonce()).resolves.toBeUndefined();
  });

  it('throws when a call requires a nonce the verifier has no source for', async () => {
    await expect(verifier().verify(check(await proof(), { requireNonce: true }))).rejects.toThrow(
      TypeError
    );
  });
});

describe('replay (RFC 9449 §11.1)', () => {
  it('refuses a proof used before', async () => {
    const value = await proof();
    const dpop = verifier();

    await expect(dpop.verify(check(value))).resolves.toBeDefined();
    await expectRefused(dpop.verify(check(value)), 'replayed');
  });

  it('refuses a new proof that reuses a jti of the same key', async () => {
    const dpop = verifier();
    await dpop.verify(check(await proof({ claims: { jti: 'same' } })));
    await expectRefused(dpop.verify(check(await proof({ claims: { jti: 'same' } }))), 'replayed');
  });

  it("does not let one key's jti block another key", async () => {
    const dpop = verifier();
    await dpop.verify(check(await proof({ claims: { jti: 'same' } })));
    const other = await testKey('ES256');
    await expect(
      dpop.verify(check(await signProof({ key: other, iat: NOW, claims: { jti: 'same' } })))
    ).resolves.toBeDefined();
  });

  it('never records a proof that failed a check', async () => {
    await refusal(verifier().verify(check(await proof(), { method: 'GET' })));
    await refusal(verifier().verify(check(await proof({ claims: { iat: NOW - 600 } }))));
    expect(store.calls).toEqual([]);
  });

  it('holds a proof until it could no longer pass the iat check', async () => {
    const value = await proof({ claims: { iat: NOW + 60 } });
    const dpop = verifier();
    await dpop.verify(check(value));

    // The last moment the proof still passes the iat check: its iat plus the
    // window, two windows after it was first used. The record outlives it.
    clock = NOW_MS + 120_000;
    await expectRefused(dpop.verify(check(value)), 'replayed');
    clock += 1;
    await expectRefused(dpop.verify(check(value)), 'iat');
  });
});

describe('the replay store unavailable', () => {
  it('refuses every proof when the store fails', async () => {
    const dpop = createDpopVerifier({
      replayStore: { record: () => Promise.reject(new Error('ECONNREFUSED')) },
      now: () => clock,
    });
    for (let i = 0; i < 3; i += 1) {
      await expectRefused(dpop.verify(check(await proof())), 'replay-store-unavailable');
    }
  });

  it('refuses the proof when the store does not answer in time', async () => {
    const dpop = createDpopVerifier({
      replayStore: { record: () => new Promise<boolean>(() => undefined) },
      replayStoreTimeoutMs: 20,
      now: () => clock,
    });
    const started = Date.now();
    await expectRefused(dpop.verify(check(await proof())), 'replay-store-unavailable');
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it('ignores a late failure of a call it gave up on', async () => {
    let fail: (error: Error) => void = () => undefined;
    const dpop = createDpopVerifier({
      replayStore: {
        record: () =>
          new Promise<boolean>((_resolve, reject) => {
            fail = reject;
          }),
      },
      replayStoreTimeoutMs: 10,
      now: () => clock,
    });
    await expectRefused(dpop.verify(check(await proof())), 'replay-store-unavailable');
    fail(new Error('late'));
    await new Promise((resolve) => setTimeout(resolve, 10));
  });

  it('refuses at creation a verifier without a store or with a timeout that is not positive', () => {
    expect(() =>
      createDpopVerifier({ replayStore: undefined as unknown as FakeReplayStore })
    ).toThrow(TypeError);
    expect(() => verifier({ replayStoreTimeoutMs: 0 })).toThrow(TypeError);
  });
});

describe('DpopProofError', () => {
  it('carries the wire code, the reason and fixed text that names nothing from the request', async () => {
    const error = await expectRefused(
      verifier().verify(check(await proof(), { method: 'GET' })),
      'htm'
    );

    expect(error.error).toBe('invalid_dpop_proof');
    expect(error.message).toBe('The DPoP proof was refused');
    expect(error.nonce).toBeUndefined();
    expect(error.name).toBe('DpopProofError');
  });
});
