import { encodeKeyAad, KEY_AAD_VERSION, type KeyAad } from '@qauth-labs/server-keys/custody';
import { describe, expect, it } from 'vitest';

import { formatCiphertext, parseCiphertext, transitContextOf } from './transit';

const AAD: KeyAad = Object.freeze({
  realmId: '7b0e9a52-6f7c-4c55-9e43-2d7f1c0a9b11',
  purpose: 'token_signing',
  scopeId: 'scope-1',
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
});

describe('the Transit context', () => {
  it('is the canonical encoding of the associated data, in base64', () => {
    expect(Buffer.from(transitContextOf(AAD), 'base64')).toEqual(encodeKeyAad(AAD));
  });

  it('differs for every field, so each binds the wrapped data key', () => {
    const contexts = [
      AAD,
      { ...AAD, realmId: '00000000-0000-4000-8000-000000000000' },
      { ...AAD, purpose: 'event_signing' },
      { ...AAD, scopeId: null },
      { ...AAD, kid: 'kid-2' },
      { ...AAD, algorithm: 'RS256' },
    ].map(transitContextOf);

    expect(new Set(contexts).size).toBe(contexts.length);
  });

  it('refuses associated data the format refuses', () => {
    expect(() => transitContextOf({ ...AAD, kid: '' })).toThrow(TypeError);
    expect(() => transitContextOf({ ...AAD, version: 99 })).toThrow(RangeError);
  });
});

describe('the Vault ciphertext', () => {
  it('is rebuilt from the stored bytes and the version, as Vault writes it', () => {
    const bytes = Buffer.from('0123456789abcdef0123456789', 'utf8');
    const text = formatCiphertext(7, bytes);

    expect(text).toBe(`vault:v7:${bytes.toString('base64')}`);
    expect(parseCiphertext(text)).toEqual({ version: 7, bytes });
  });

  it.each([
    undefined,
    42,
    'vault:v1:',
    'vault:v0:QUJD',
    'vault:v1:QUJD!',
    'vault:v1:QUJ',
    'vault:v1:QUI=x',
    'vault:v1:QR==',
    'vault:v1:QUJD\n',
    'vault:vx:QUJD',
    'other:v1:QUJD',
  ])('reads %j as no Vault ciphertext', (text) => {
    expect(parseCiphertext(text)).toBeUndefined();
  });
});
