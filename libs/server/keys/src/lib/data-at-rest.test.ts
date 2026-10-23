import { describe, expect, it } from 'vitest';

import {
  dataAad,
  isDataKid,
  MAX_DATA_CONTEXT_LENGTH,
  openData,
  parseDataEnvelope,
  resolveDataContext,
  sealData,
} from './data-at-rest';
import { DataDecryptionError, SignerRequestRefusedError } from './signer-errors';

const REALM = '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01';
const KID = 'AAECAwQFBgcICQoLDA0ODw';

function aesKey(fill: number): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', Buffer.alloc(32, fill), 'AES-GCM', false, [
    'encrypt',
    'decrypt',
  ]);
}

describe('dataAad', () => {
  it('is the label, the version and three length-prefixed fields (test vector)', () => {
    expect(dataAad('r', 'k', '').toString('hex')).toBe(
      Buffer.from('qauth/data-at-rest', 'ascii').toString('hex') +
        '01' +
        '00000001' +
        '72' +
        '00000001' +
        '6b' +
        '00000000'
    );
  });

  it('tells apart fields that would concatenate alike', () => {
    expect(dataAad('ab', 'c', '').equals(dataAad('a', 'bc', ''))).toBe(false);
    expect(dataAad(REALM, KID, 'x').equals(dataAad(REALM, KID, ''))).toBe(false);
  });
});

describe('sealData and openData', () => {
  it('round-trip under the same realm, kid and context', async () => {
    const key = await aesKey(1);
    const ciphertext = await sealData(key, KID, REALM, 'ctx', Buffer.from('secret'));
    const envelope = parseDataEnvelope(ciphertext);

    expect(envelope.kid).toBe(KID);
    expect(envelope.iv).toHaveLength(12);
    expect(envelope.body).toHaveLength('secret'.length + 16);
    expect(await openData(key, envelope, REALM, 'ctx')).toEqual(Buffer.from('secret'));
  });

  it('refuses another key, realm or context', async () => {
    const key = await aesKey(1);
    const envelope = parseDataEnvelope(await sealData(key, KID, REALM, 'ctx', Buffer.from('s')));

    await expect(openData(await aesKey(2), envelope, REALM, 'ctx')).rejects.toBeInstanceOf(
      DataDecryptionError
    );
    await expect(
      openData(key, envelope, '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02', 'ctx')
    ).rejects.toBeInstanceOf(DataDecryptionError);
    await expect(openData(key, envelope, REALM, 'other')).rejects.toBeInstanceOf(
      DataDecryptionError
    );
  });

  it('refuses a ciphertext whose kid was swapped', async () => {
    const key = await aesKey(1);
    const ciphertext = await sealData(key, KID, REALM, '', Buffer.from('s'));
    const swapped = parseDataEnvelope(ciphertext.replace(KID, 'another-kid'));

    await expect(openData(key, swapped, REALM, '')).rejects.toBeInstanceOf(DataDecryptionError);
  });
});

describe('parseDataEnvelope', () => {
  it.each([
    ['not a string', 42],
    ['empty', ''],
    ['another version', `v2.${KID}.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA`],
    ['three parts', `v1.${KID}.AAAAAAAAAAAAAAAA`],
    [
      'a kid with a dot-free but invalid character',
      `v1.k!d.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA`,
    ],
    ['a short nonce', `v1.${KID}.AAAA.AAAAAAAAAAAAAAAAAAAAAA`],
    ['a body shorter than the tag', `v1.${KID}.AAAAAAAAAAAAAAAA.AAAA`],
    ['padding characters', `v1.${KID}.AAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAA==`],
  ])('refuses %s', (_, ciphertext) => {
    expect(() => parseDataEnvelope(ciphertext)).toThrow(DataDecryptionError);
  });
});

describe('resolveDataContext', () => {
  it('defaults to the empty string', () => {
    expect(resolveDataContext(undefined)).toBe('');
  });

  it.each([1, null, 'x'.repeat(MAX_DATA_CONTEXT_LENGTH + 1), '\uDC00'])('refuses %o', (context) => {
    expect(() => resolveDataContext(context)).toThrow(SignerRequestRefusedError);
  });

  it('takes a context of the maximum length', () => {
    const context = 'x'.repeat(MAX_DATA_CONTEXT_LENGTH);
    expect(resolveDataContext(context)).toBe(context);
  });
});

describe('isDataKid', () => {
  it.each([
    [KID, true],
    ['a.b', false],
    ['', false],
    ['x'.repeat(256), false],
  ])('%s → %s', (kid, expected) => {
    expect(isDataKid(kid)).toBe(expected);
  });
});
