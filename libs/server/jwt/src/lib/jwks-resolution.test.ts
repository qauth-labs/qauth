import { describe, expect, it } from 'vitest';

import { assertDistinctJwksKeyIds, type PublishedJwk, selectJwksKey } from './jwks-resolution';

const okp = (kid?: string): PublishedJwk => ({
  kty: 'OKP',
  crv: 'Ed25519',
  x: 'x-bytes',
  use: 'sig',
  alg: 'EdDSA',
  ...(kid !== undefined ? { kid } : {}),
});

const akp = (kid?: string): PublishedJwk => ({
  kty: 'AKP',
  pub: 'pub-bytes',
  use: 'sig',
  alg: 'ML-DSA-65',
  ...(kid !== undefined ? { kid } : {}),
});

describe('selectJwksKey — resolution is keyed on (kid, alg), never kid alone (#248 F9)', () => {
  it('resolves the OKP and AKP entries of a hybrid JWKS to different keys', () => {
    const keys = [okp('ed-2026'), akp('mldsa-2026')];

    expect(selectJwksKey(keys, { kid: 'ed-2026', alg: 'EdDSA' })).toBe(keys[0]);
    expect(selectJwksKey(keys, { kid: 'mldsa-2026', alg: 'ML-DSA-65' })).toBe(keys[1]);
  });

  it('REFUSES a kid/alg mismatch — the algorithm-confusion case kid-alone allows', () => {
    // This is the whole point of the finding: an ML-DSA kid asked for as EdDSA
    // must not resolve to the ML-DSA key (nor to the Ed25519 one).
    const keys = [okp('ed-2026'), akp('mldsa-2026')];

    expect(selectJwksKey(keys, { kid: 'mldsa-2026', alg: 'EdDSA' })).toBeUndefined();
    expect(selectJwksKey(keys, { kid: 'ed-2026', alg: 'ML-DSA-65' })).toBeUndefined();
  });

  it('distinguishes same-kid entries by algorithm instead of returning the first match', () => {
    // A JWKS this server would refuse to publish (see assertDistinctJwksKeyIds),
    // but a FEDERATED one may look like this — resolution must still be exact.
    const keys = [okp('shared'), akp('shared')];

    expect(selectJwksKey(keys, { kid: 'shared', alg: 'EdDSA' })).toBe(keys[0]);
    expect(selectJwksKey(keys, { kid: 'shared', alg: 'ML-DSA-65' })).toBe(keys[1]);
  });

  it('resolves a retired key by its own kid alongside the active one', () => {
    const keys = [okp('ed-2026'), okp('ed-2025'), akp('mldsa-2026')];

    expect(selectJwksKey(keys, { kid: 'ed-2025', alg: 'EdDSA' })).toBe(keys[1]);
    expect(selectJwksKey(keys, { kid: 'ed-2026', alg: 'EdDSA' })).toBe(keys[0]);
  });

  it('returns undefined for an unknown kid rather than falling back to any key', () => {
    expect(
      selectJwksKey([okp('ed-2026'), akp('mldsa-2026')], { kid: 'ed-2024', alg: 'EdDSA' })
    ).toBeUndefined();
  });

  it('resolves without a kid ONLY while one key of that algorithm exists', () => {
    const single = [okp(), akp()];
    expect(selectJwksKey(single, { alg: 'EdDSA' })).toBe(single[0]);
    expect(selectJwksKey(single, { alg: 'ML-DSA-65' })).toBe(single[1]);

    // Once rotation publishes a second EdDSA key, an unkeyed selector is
    // ambiguous and must fail closed rather than guess the active one.
    expect(selectJwksKey([okp('ed-2026'), okp('ed-2025')], { alg: 'EdDSA' })).toBeUndefined();
  });

  it('rejects an entry whose kty contradicts its alg (tampered/malformed JWKS)', () => {
    // Deliberately ill-typed: only an external/tampered JWKS can look like this,
    // which is exactly the input `selectJwksKey` has to survive.
    const lying = { ...akp('mldsa-2026'), kty: 'OKP' } as unknown as PublishedJwk;
    expect(selectJwksKey([lying], { kid: 'mldsa-2026', alg: 'ML-DSA-65' })).toBeUndefined();

    const alsoLying = { ...okp('ed-2026'), kty: 'AKP' } as unknown as PublishedJwk;
    expect(selectJwksKey([alsoLying], { kid: 'ed-2026', alg: 'EdDSA' })).toBeUndefined();
  });

  it('returns undefined for an empty JWKS', () => {
    expect(selectJwksKey([], { kid: 'ed-2026', alg: 'EdDSA' })).toBeUndefined();
  });
});

describe('assertDistinctJwksKeyIds — the JWKS this server publishes (#248 F9)', () => {
  it('accepts an active + retired + AKP set with distinct kids', () => {
    expect(() =>
      assertDistinctJwksKeyIds([
        okp('ed-2026'),
        okp('ed-2025'),
        akp('mldsa-2026'),
        akp('mldsa-2025'),
      ])
    ).not.toThrow();
  });

  it('rejects a kid reused ACROSS the OKP and AKP halves', () => {
    // Stock JOSE clients do select on kid alone, so a kid shared by two
    // algorithms is a trap even though selectJwksKey itself copes.
    expect(() => assertDistinctJwksKeyIds([okp('key-1'), akp('key-1')])).toThrow(
      /duplicate kid 'key-1'/
    );
  });

  it('rejects a kid reused between an active and a retired key of the same algorithm', () => {
    expect(() => assertDistinctJwksKeyIds([okp('ed-2026'), okp('ed-2026')])).toThrow(
      /duplicate kid 'ed-2026'/
    );
  });

  it('allows the legacy single-key shape with no kid at all', () => {
    expect(() => assertDistinctJwksKeyIds([okp()])).not.toThrow();
    expect(() => assertDistinctJwksKeyIds([okp(), akp()])).not.toThrow();
  });

  it('rejects two un-kid-ed keys of the same algorithm (mutually unaddressable)', () => {
    expect(() => assertDistinctJwksKeyIds([okp(), okp()])).toThrow(/without a kid/);
  });
});
