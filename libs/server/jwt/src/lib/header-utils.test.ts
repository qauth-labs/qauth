import { describe, expect, it } from 'vitest';

import { extractAccessTokenCredential, extractJWTFromHeader } from './header-utils';

describe('extractAccessTokenCredential (RFC 6750 §2.1, RFC 9449 §7.1)', () => {
  it('reads a Bearer token whether or not DPoP is allowed', () => {
    expect(extractAccessTokenCredential('Bearer abc')).toEqual({ scheme: 'Bearer', token: 'abc' });
    expect(extractAccessTokenCredential('Bearer abc', { allowDpop: true })).toEqual({
      scheme: 'Bearer',
      token: 'abc',
    });
  });

  it('reads a DPoP token only when DPoP is allowed', () => {
    expect(extractAccessTokenCredential('DPoP abc')).toBeNull();
    expect(extractAccessTokenCredential('DPoP abc', { allowDpop: true })).toEqual({
      scheme: 'DPoP',
      token: 'abc',
    });
  });

  it.each([
    ['no header', undefined],
    ['an empty header', ''],
    ['an empty Bearer token', 'Bearer '],
    ['an empty DPoP token', 'DPoP '],
    ['another scheme', 'Basic YTpi'],
    ['a lower-case scheme', 'dpop abc'],
    ['two tokens', 'DPoP a b'],
  ])('reads no credential from %s', (_name, header) => {
    expect(extractAccessTokenCredential(header, { allowDpop: true })).toBeNull();
  });

  it('agrees with extractJWTFromHeader on every Bearer header', () => {
    for (const header of ['Bearer abc', 'Bearer ', 'bearer abc', 'Bearer a b', undefined]) {
      const credential = extractAccessTokenCredential(header);
      expect(credential?.token ?? null).toBe(extractJWTFromHeader(header) || null);
    }
  });
});
