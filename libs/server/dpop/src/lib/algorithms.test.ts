import { describe, expect, it } from 'vitest';

import {
  DEFAULT_DPOP_ALGORITHMS,
  DPOP_SIGNATURE_ALGORITHMS,
  isDpopAlgorithm,
  keyFitsAlgorithm,
} from './algorithms';

/** The DPoP algorithm allowlists (RFC 9449 §4.2, §11.6). */
describe('the DPoP algorithms', () => {
  it('lists asymmetric signature algorithms only', () => {
    for (const alg of ['none', 'HS256', 'HS384', 'HS512', 'dir', 'RSA-OAEP']) {
      expect(isDpopAlgorithm(alg)).toBe(false);
    }
    expect(DPOP_SIGNATURE_ALGORITHMS.every((alg) => isDpopAlgorithm(alg))).toBe(true);
  });

  it('leaves RSASSA-PKCS1-v1_5 out of the default and keeps the rest', () => {
    expect([...DEFAULT_DPOP_ALGORITHMS].sort()).toEqual(
      DPOP_SIGNATURE_ALGORITHMS.filter((alg) => !alg.startsWith('RS')).sort()
    );
  });

  it.each([
    ['ES256', { kty: 'EC', crv: 'P-256' }, true],
    ['ES256', { kty: 'EC', crv: 'P-384' }, false],
    ['ES384', { kty: 'EC', crv: 'P-384' }, true],
    ['ES512', { kty: 'EC', crv: 'P-521' }, true],
    ['EdDSA', { kty: 'OKP', crv: 'Ed25519' }, true],
    ['EdDSA', { kty: 'OKP', crv: 'Ed448' }, false],
    ['Ed25519', { kty: 'OKP', crv: 'Ed25519' }, true],
    ['PS256', { kty: 'RSA' }, true],
    ['RS256', { kty: 'EC', crv: 'P-256' }, false],
    ['ES256', { kty: 'OKP', crv: 'Ed25519' }, false],
  ] as const)('%s with %j fits: %s', (alg, jwk, fits) => {
    expect(keyFitsAlgorithm(alg, jwk)).toBe(fits);
  });
});
