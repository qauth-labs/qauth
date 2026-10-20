import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import { encodeKeyAad, type KeyAad } from './aad';
import { DATA_KEY_BYTES, IV_BYTES, TAG_BYTES } from './envelope';
import { KeyDecryptionError, UnknownKekRefError } from './errors';
import type {
  KekProvider,
  KekProviderContext,
  KekProviderHealth,
  WrappedDataKey,
} from './kek-provider';
import { type LocalKek, readLocalKeks } from './kek-sources';

/** The `KEK_PROVIDER` value of the default provider. */
export const LOCAL_KEK_PROVIDER = 'local';

/** The first byte of a data key this provider wrapped: its format. */
const WRAP_FORMAT = 0x01;

/** Format byte, nonce, wrapped data key, tag. */
const WRAPPED_BYTES = 1 + IV_BYTES + DATA_KEY_BYTES + TAG_BYTES;

/**
 * The default KEK provider: the KEK sits in this process's memory, read from
 * `KEK` or `KEK_PATH` (ADR-019 Decision 9).
 *
 * A data key is wrapped with AES-256-GCM under the current KEK, bound to the
 * key's associated data. The result is one format byte (`0x01`), the 12-byte
 * nonce, the 32-byte wrapped key and the 16-byte tag. `kekRef` is the KEK's
 * fingerprint, so `KEK_PREVIOUS` or `KEK_PREVIOUS_PATH` keeps rows wrapped
 * before a KEK rotation open until they are re-wrapped.
 *
 * The KEKs are held in closures as key objects: the provider object has no
 * property that holds or prints them.
 *
 * @throws InvalidConfigurationError when the KEK settings cannot be used. See
 *   {@link readLocalKeks}.
 */
export function createLocalKekProvider(context: KekProviderContext): KekProvider {
  const { current, previous } = readLocalKeks(context.env, context.warn);
  const keks = new Map<string, LocalKek>([[current.ref, current]]);
  if (previous !== undefined && !keks.has(previous.ref)) keks.set(previous.ref, previous);

  return Object.freeze({
    name: LOCAL_KEK_PROVIDER,

    async wrap(dek: Uint8Array, aad: KeyAad): Promise<WrappedDataKey> {
      if (dek.length !== DATA_KEY_BYTES) {
        throw new RangeError(`A data key must be ${DATA_KEY_BYTES} bytes`);
      }
      const aadBytes = encodeKeyAad(aad);
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', current.key, iv, { authTagLength: TAG_BYTES });
      cipher.setAAD(aadBytes);
      const body = Buffer.concat([cipher.update(dek), cipher.final()]);
      return Object.freeze({
        wrapped: Buffer.concat([Buffer.from([WRAP_FORMAT]), iv, body, cipher.getAuthTag()]),
        kekRef: current.ref,
      });
    },

    async unwrap(wrapped: Uint8Array, aad: KeyAad, kekRef: string): Promise<Uint8Array> {
      const kek = keks.get(kekRef);
      if (kek === undefined) throw new UnknownKekRefError(kekRef);

      let aadBytes: Buffer;
      try {
        aadBytes = encodeKeyAad(aad);
      } catch (error) {
        throw new KeyDecryptionError({ detail: 'unusable associated data', cause: error });
      }
      if (wrapped.length !== WRAPPED_BYTES || wrapped[0] !== WRAP_FORMAT) {
        throw new KeyDecryptionError({ detail: 'malformed wrapped data key' });
      }

      const iv = wrapped.subarray(1, 1 + IV_BYTES);
      const body = wrapped.subarray(1 + IV_BYTES, 1 + IV_BYTES + DATA_KEY_BYTES);
      const tag = wrapped.subarray(1 + IV_BYTES + DATA_KEY_BYTES);
      const decipher = createDecipheriv('aes-256-gcm', kek.key, iv, { authTagLength: TAG_BYTES });
      decipher.setAAD(aadBytes);
      decipher.setAuthTag(tag);
      try {
        return Buffer.concat([decipher.update(body), decipher.final()]);
      } catch (error) {
        throw new KeyDecryptionError({ detail: 'data key did not authenticate', cause: error });
      }
    },

    async health(): Promise<KekProviderHealth> {
      return Object.freeze({ ok: true, provider: LOCAL_KEK_PROVIDER, kekRef: current.ref });
    },
  });
}
