import { describe, expect, it } from 'vitest';

import { encodeKeyAad, KEY_AAD_VERSION, type KeyAad, keyAad, type KeyIdentity } from './aad';

const IDENTITY: KeyIdentity = {
  realmId: 'realm-1',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
};

const AAD: KeyAad = { ...IDENTITY, version: KEY_AAD_VERSION };

describe('encodeKeyAad', () => {
  /**
   * Stored rows open only while the encoding stays the same, so these bytes
   * are written out rather than computed. The vectors were produced by a
   * separate script from the format in the docblock, not by this code.
   */
  it('encodes format 1 byte for byte', () => {
    expect(encodeKeyAad(AAD).toString('hex')).toBe(
      '71617574682f6b65792d616164' + // "qauth/key-aad"
        '01' + // version
        '01' +
        '00000007' +
        '7265616c6d2d31' + // realmId "realm-1"
        '01' +
        '0000000d' +
        '746f6b656e5f7369676e696e67' + // purpose "token_signing"
        '00' + // no scopeId
        '01' +
        '00000005' +
        '6b69642d31' + // kid "kid-1"
        '01' +
        '00000005' +
        '4564445341' // algorithm "EdDSA"
    );
    expect(
      encodeKeyAad({
        realmId: 'realm-1',
        purpose: 'webhook_signing',
        scopeId: 'sub-9',
        kid: 'kid-2',
        algorithm: 'ES256',
        version: 1,
      }).toString('hex')
    ).toBe(
      '71617574682f6b65792d6161640101000000077265616c6d2d31010000000f776562686f6f6b5f7369676e696e6701000000057375622d3901000000056b69642d3201000000054553323536'
    );
  });

  it.each([
    ['realmId', { realmId: 'realm-2' }],
    ['purpose', { purpose: 'event_signing' }],
    ['scopeId', { scopeId: 'subscription-1' }],
    ['kid', { kid: 'kid-2' }],
    ['algorithm', { algorithm: 'RS256' }],
  ] as const)('changes when %s changes', (_field, change) => {
    expect(encodeKeyAad({ ...AAD, ...change }).equals(encodeKeyAad(AAD))).toBe(false);
  });

  it('keeps field boundaries apart, so moving a character between fields changes the bytes', () => {
    const left = encodeKeyAad({ ...AAD, realmId: 'ab', purpose: 'c' });
    const right = encodeKeyAad({ ...AAD, realmId: 'a', purpose: 'bc' });

    expect(left.equals(right)).toBe(false);
  });

  it('refuses an empty field, so an empty scopeId cannot stand in for none', () => {
    expect(() => encodeKeyAad({ ...AAD, scopeId: '' })).toThrow(TypeError);
    expect(() => encodeKeyAad({ ...AAD, realmId: '' })).toThrow(TypeError);
    expect(() => encodeKeyAad({ ...AAD, kid: '' })).toThrow(TypeError);
  });

  it('refuses null for every field but scopeId', () => {
    for (const field of ['realmId', 'purpose', 'kid', 'algorithm'] as const) {
      expect(() => encodeKeyAad({ ...AAD, [field]: null as unknown as string })).toThrow(TypeError);
    }
  });

  it('refuses a lone surrogate, which UTF-8 would turn into U+FFFD', () => {
    expect(() => encodeKeyAad({ ...AAD, kid: 'kid-\ud800' })).toThrow(TypeError);
    expect(encodeKeyAad({ ...AAD, kid: 'kid-\ud83d\udd11' })).toBeInstanceOf(Buffer);
  });

  it('refuses a version it has no format for', () => {
    expect(() => encodeKeyAad({ ...AAD, version: 2 })).toThrow(RangeError);
    expect(() => encodeKeyAad({ ...AAD, version: 0 })).toThrow(RangeError);
  });
});

describe('keyAad', () => {
  it('copies exactly the identity fields and the version, so no other column reaches a provider', () => {
    const row = { ...IDENTITY, ciphertext: Buffer.from('secret'), status: 'active' };

    expect(keyAad(row, KEY_AAD_VERSION)).toEqual(AAD);
    expect(Object.isFrozen(keyAad(row, KEY_AAD_VERSION))).toBe(true);
  });
});
