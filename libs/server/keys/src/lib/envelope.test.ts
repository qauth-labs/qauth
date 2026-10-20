import { createDecipheriv, randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import { KEK_A, KEK_B, localProvider } from '../testing/keks';
import { encodeKeyAad, KEY_AAD_VERSION, type KeyAad, type KeyIdentity } from './aad';
import {
  DATA_KEY_BYTES,
  IV_BYTES,
  openKeyMaterial,
  type SealedKeyMaterial,
  sealKeyMaterial,
  TAG_BYTES,
} from './envelope';
import { KEY_DECRYPTION_ERROR_MESSAGE, KeyDecryptionError, UnknownKekRefError } from './errors';
import type { KekProvider } from './kek-provider';

const REALM_A: KeyIdentity = {
  realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e01',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs',
  algorithm: 'EdDSA',
};

const REALM_B: KeyIdentity = { ...REALM_A, realmId: '0190d7a2-6f4e-7c1a-9b3e-5a8d2c4f6e02' };

/** A PKCS#8 Ed25519 private key's worth of bytes. */
const MATERIAL = randomBytes(48);

/** A copy of `sealed` with one field replaced. */
function withField<K extends keyof SealedKeyMaterial>(
  sealed: SealedKeyMaterial,
  key: K,
  value: SealedKeyMaterial[K]
): SealedKeyMaterial {
  return { ...sealed, [key]: value };
}

function flipped(bytes: Buffer, index: number): Buffer {
  const copy = Buffer.from(bytes);
  copy[index] ^= 0x01;
  return copy;
}

describe('sealKeyMaterial and openKeyMaterial', () => {
  const provider = localProvider({ KEK: KEK_A });

  it('return the same bytes after a round trip', async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);

    expect(await openKeyMaterial(provider, sealed, REALM_A)).toEqual(MATERIAL);
  });

  it('store the shape realm_keys holds: ciphertext with its tag, a 12-byte IV, the wrapped data key and its kekRef', async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);
    const { kekRef } = await provider.health();

    expect(sealed.iv).toHaveLength(IV_BYTES);
    expect(sealed.ciphertext).toHaveLength(MATERIAL.length + TAG_BYTES);
    expect(sealed.kekRef).toBe(kekRef);
    expect(sealed.aadVersion).toBe(KEY_AAD_VERSION);
    expect(sealed.ciphertext.includes(MATERIAL)).toBe(false);
  });

  it('encrypt the material with AES-256-GCM under the data key, authenticating the encoded associated data', async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);
    const aad = { ...REALM_A, version: sealed.aadVersion };
    const dek = await provider.unwrap(sealed.wrappedDek, aad, sealed.kekRef);
    const body = sealed.ciphertext.subarray(0, -TAG_BYTES);
    const tag = sealed.ciphertext.subarray(-TAG_BYTES);
    const decrypt = (associatedData: Buffer | undefined) => {
      const decipher = createDecipheriv('aes-256-gcm', dek, sealed.iv, {
        authTagLength: TAG_BYTES,
      });
      if (associatedData !== undefined) decipher.setAAD(associatedData);
      decipher.setAuthTag(tag);
      return Buffer.concat([decipher.update(body), decipher.final()]);
    };

    expect(decrypt(encodeKeyAad(aad))).toEqual(MATERIAL);
    expect(() => decrypt(undefined)).toThrow();
    expect(() => decrypt(encodeKeyAad({ ...aad, realmId: REALM_B.realmId }))).toThrow();
  });

  it('use a fresh data key and IV for every seal', async () => {
    const first = await sealKeyMaterial(provider, MATERIAL, REALM_A);
    const second = await sealKeyMaterial(provider, MATERIAL, REALM_A);

    expect(first.iv.equals(second.iv)).toBe(false);
    expect(first.wrappedDek.equals(second.wrappedDek)).toBe(false);
    expect(first.ciphertext.equals(second.ciphertext)).toBe(false);
  });

  it('give the provider a 256-bit data key, bound to the identity, and zero it afterwards', async () => {
    const seen: { dek?: Uint8Array; copy?: Buffer; aad?: KeyAad } = {};
    const spy: KekProvider = {
      ...provider,
      wrap: async (dek, aad) => {
        seen.dek = dek;
        seen.copy = Buffer.from(dek);
        seen.aad = aad;
        return provider.wrap(dek, aad);
      },
    };

    await sealKeyMaterial(spy, MATERIAL, { ...REALM_A, status: 'active' } as KeyIdentity);

    expect(seen.copy).toHaveLength(DATA_KEY_BYTES);
    expect(seen.copy?.equals(Buffer.alloc(DATA_KEY_BYTES))).toBe(false);
    expect(Buffer.from(seen.dek ?? []).equals(Buffer.alloc(DATA_KEY_BYTES))).toBe(true);
    expect(seen.aad).toEqual({ ...REALM_A, version: KEY_AAD_VERSION });
  });
});

describe('openKeyMaterial refuses', () => {
  const provider = localProvider({ KEK: KEK_A });

  it("material sealed for realm A under realm B's associated data", async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);

    await expect(openKeyMaterial(provider, sealed, REALM_B)).rejects.toThrow(KeyDecryptionError);
  });

  it.each([
    ['purpose', { purpose: 'event_signing' }],
    ['scopeId', { scopeId: 'subscription-1' }],
    ['kid', { kid: 'another-kid' }],
    ['algorithm', { algorithm: 'ML-DSA-65' }],
  ] as const)('associated data with another %s', async (_field, change) => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);

    await expect(openKeyMaterial(provider, sealed, { ...REALM_A, ...change })).rejects.toThrow(
      KeyDecryptionError
    );
  });

  it('another associated-data version', async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);

    await expect(
      openKeyMaterial(provider, withField(sealed, 'aadVersion', 2), REALM_A)
    ).rejects.toThrow(KeyDecryptionError);
  });

  it('a wrong KEK: a provider without the KEK that wrapped the data key', async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);
    const other = localProvider({ KEK: KEK_B });

    await expect(openKeyMaterial(other, sealed, REALM_A)).rejects.toThrow(UnknownKekRefError);
  });

  it("a wrong KEK: the other KEK's reference on a data key it did not wrap", async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);
    const other = localProvider({ KEK: KEK_B });
    const { kekRef } = await other.health();

    await expect(
      openKeyMaterial(other, withField(sealed, 'kekRef', kekRef ?? ''), REALM_A)
    ).rejects.toThrow(KeyDecryptionError);
  });

  it.each([
    [
      'the first ciphertext byte',
      (s: SealedKeyMaterial) => withField(s, 'ciphertext', flipped(s.ciphertext, 0)),
    ],
    [
      'the tag',
      (s: SealedKeyMaterial) =>
        withField(s, 'ciphertext', flipped(s.ciphertext, s.ciphertext.length - 1)),
    ],
    ['the IV', (s: SealedKeyMaterial) => withField(s, 'iv', flipped(s.iv, 0))],
    [
      'the wrapped data key',
      (s: SealedKeyMaterial) => withField(s, 'wrappedDek', flipped(s.wrappedDek, 20)),
    ],
    [
      'a truncated ciphertext',
      (s: SealedKeyMaterial) => withField(s, 'ciphertext', s.ciphertext.subarray(0, TAG_BYTES - 1)),
    ],
    ['a short IV', (s: SealedKeyMaterial) => withField(s, 'iv', s.iv.subarray(0, IV_BYTES - 1))],
  ])('tampered material: %s', async (_what, tamper) => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);

    await expect(openKeyMaterial(provider, tamper(sealed), REALM_A)).rejects.toThrow(
      KeyDecryptionError
    );
  });

  it('with one fixed message for every cause, so no failure can be told from another', async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);
    const failures = await Promise.all([
      openKeyMaterial(provider, sealed, REALM_B).catch((error: unknown) => error),
      openKeyMaterial(provider, withField(sealed, 'iv', flipped(sealed.iv, 0)), REALM_A).catch(
        (error: unknown) => error
      ),
      openKeyMaterial(
        provider,
        withField(sealed, 'wrappedDek', flipped(sealed.wrappedDek, 20)),
        REALM_A
      ).catch((error: unknown) => error),
    ]);

    for (const failure of failures) {
      expect(failure).toBeInstanceOf(KeyDecryptionError);
      expect((failure as Error).message).toBe(KEY_DECRYPTION_ERROR_MESSAGE);
    }
  });

  it('a data key of the wrong length from a provider', async () => {
    const sealed = await sealKeyMaterial(provider, MATERIAL, REALM_A);
    const short: KekProvider = { ...provider, unwrap: async () => Buffer.alloc(16) };

    await expect(openKeyMaterial(short, sealed, REALM_A)).rejects.toThrow(KeyDecryptionError);
  });
});
