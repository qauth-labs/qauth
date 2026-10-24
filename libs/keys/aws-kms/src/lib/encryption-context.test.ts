import { KEY_AAD_VERSION, type KeyAad } from '@qauth-labs/server-keys/custody';
import { describe, expect, it } from 'vitest';

import { ENCRYPTION_CONTEXT_KEYS, encryptionContextOf } from './encryption-context';

const AAD: KeyAad = {
  realmId: 'realm-a',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
};

describe('encryptionContextOf', () => {
  // Stored keys open only while these keys stay as they are: a change here is
  // a new associated-data format, never an edit.
  it('pins the encryption-context keys', () => {
    expect(ENCRYPTION_CONTEXT_KEYS).toEqual({
      version: 'qauth:aad-version',
      realmId: 'qauth:realm-id',
      purpose: 'qauth:purpose',
      scopeId: 'qauth:scope-id',
      kid: 'qauth:kid',
      algorithm: 'qauth:algorithm',
    });
  });

  it('maps an unscoped key to one pair per field, without a scope pair', () => {
    expect(encryptionContextOf(AAD)).toEqual({
      'qauth:aad-version': '1',
      'qauth:realm-id': 'realm-a',
      'qauth:purpose': 'token_signing',
      'qauth:kid': 'kid-1',
      'qauth:algorithm': 'EdDSA',
    });
  });

  it('adds the scope pair for a scoped key', () => {
    expect(
      encryptionContextOf({ ...AAD, purpose: 'webhook_signing', scopeId: 'subscription-1' })
    ).toMatchObject({ 'qauth:purpose': 'webhook_signing', 'qauth:scope-id': 'subscription-1' });
  });

  it('copies only the associated-data fields of a wider object', () => {
    const row = { ...AAD, ciphertext: 'not-for-kms', status: 'active' } as KeyAad;

    expect(Object.keys(encryptionContextOf(row))).toHaveLength(5);
  });

  it('refuses what the associated-data format refuses', () => {
    expect(() => encryptionContextOf({ ...AAD, scopeId: '' })).toThrow(TypeError);
    expect(() => encryptionContextOf({ ...AAD, realmId: '' })).toThrow(TypeError);
    expect(() => encryptionContextOf({ ...AAD, kid: 'lone-\ud800' })).toThrow(TypeError);
    expect(() => encryptionContextOf({ ...AAD, version: 2 })).toThrow(RangeError);
  });
});
