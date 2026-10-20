import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import { encodeKeyAad, KEY_AAD_VERSION, keyAad, type KeyIdentity } from './aad';
import { KeyDecryptionError } from './errors';
import { finishGcmDecryption } from './gcm';
import type { KekProvider } from './kek-provider';

/**
 * Envelope encryption of stored key material (ADR-019 Decision 9, NIST
 * SP 800-38D).
 *
 * Each key gets its own random 256-bit data key (DEK). The DEK encrypts the
 * material with AES-256-GCM, and the KEK provider wraps the DEK. A KEK rotation
 * therefore re-wraps only the DEKs; the material stays as it is.
 */

/** The cipher for the material. */
const CIPHER = 'aes-256-gcm';
/** A data key is 256 bits. */
export const DATA_KEY_BYTES = 32;
/** The GCM nonce: 96 bits, random per seal (SP 800-38D §8.2.2). */
export const IV_BYTES = 12;
/** The full 128-bit GCM tag. */
export const TAG_BYTES = 16;

/**
 * Sealed key material, as `realm_keys` stores it. Nothing in it is secret on
 * its own: opening it needs the KEK.
 */
export interface SealedKeyMaterial {
  /** The `ciphertext` column: the AES-256-GCM ciphertext, then its 16-byte tag. */
  readonly ciphertext: Buffer;
  /** The `iv` column: the 12-byte GCM nonce. */
  readonly iv: Buffer;
  /** The `wrapped_dek` column: the data key, wrapped by the KEK provider. */
  readonly wrappedDek: Buffer;
  /** The `kek_ref` column: the KEK that wrapped the data key. */
  readonly kekRef: string;
  /** The `aad_version` column: the associated-data format. */
  readonly aadVersion: number;
}

/**
 * Encrypt key material for one stored key.
 *
 * @param provider - wraps the fresh data key
 * @param material - the plaintext key material, such as a PKCS#8 private key
 * @param identity - the row the material belongs to. It is bound into the
 *   associated data, so the result opens only for this same identity.
 */
export async function sealKeyMaterial(
  provider: KekProvider,
  material: Uint8Array,
  identity: KeyIdentity
): Promise<SealedKeyMaterial> {
  const aad = keyAad(identity, KEY_AAD_VERSION);
  const aadBytes = encodeKeyAad(aad);
  const dek = randomBytes(DATA_KEY_BYTES);

  try {
    const iv = randomBytes(IV_BYTES);
    const cipher = createCipheriv(CIPHER, dek, iv, { authTagLength: TAG_BYTES });
    cipher.setAAD(aadBytes);
    const ciphertext = Buffer.concat([
      cipher.update(material),
      cipher.final(),
      cipher.getAuthTag(),
    ]);

    const { wrapped, kekRef } = await provider.wrap(dek, aad);

    return Object.freeze({
      ciphertext,
      iv,
      wrappedDek: Buffer.from(wrapped),
      kekRef,
      aadVersion: KEY_AAD_VERSION,
    });
  } finally {
    dek.fill(0);
  }
}

/**
 * Decrypt the material of one stored key.
 *
 * @param identity - the row's identity, read from the row itself. It must be
 *   the identity the material was sealed with.
 * @returns the plaintext material, in a buffer that belongs to the caller.
 *   Zero it once the key has been imported.
 * @throws KeyDecryptionError when the associated data, the wrapped data key or
 *   the ciphertext does not match, or the row is malformed
 * @throws UnknownKekRefError when the provider holds no KEK named by `kekRef`
 */
export async function openKeyMaterial(
  provider: KekProvider,
  sealed: SealedKeyMaterial,
  identity: KeyIdentity
): Promise<Buffer> {
  let aadBytes: Buffer;
  const aad = keyAad(identity, sealed.aadVersion);
  try {
    aadBytes = encodeKeyAad(aad);
  } catch (error) {
    throw new KeyDecryptionError({ detail: 'unusable associated data', cause: error });
  }

  if (sealed.iv.length !== IV_BYTES || sealed.ciphertext.length < TAG_BYTES) {
    throw new KeyDecryptionError({ detail: 'malformed sealed material' });
  }

  // A view, not a copy, so the `fill(0)` below clears the bytes the provider
  // returned rather than a duplicate of them. They belong to this caller (see
  // `KekProvider.unwrap`).
  const unwrapped = await provider.unwrap(sealed.wrappedDek, aad, sealed.kekRef);
  const dek = Buffer.from(unwrapped.buffer, unwrapped.byteOffset, unwrapped.byteLength);
  try {
    if (dek.length !== DATA_KEY_BYTES) {
      throw new KeyDecryptionError({ detail: 'unwrapped data key has the wrong length' });
    }
    const body = sealed.ciphertext.subarray(0, sealed.ciphertext.length - TAG_BYTES);
    const tag = sealed.ciphertext.subarray(sealed.ciphertext.length - TAG_BYTES);
    const decipher = createDecipheriv(CIPHER, dek, sealed.iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(aadBytes);
    decipher.setAuthTag(tag);
    try {
      return finishGcmDecryption(decipher, body);
    } catch (error) {
      throw new KeyDecryptionError({ detail: 'material did not authenticate', cause: error });
    }
  } finally {
    dek.fill(0);
  }
}
