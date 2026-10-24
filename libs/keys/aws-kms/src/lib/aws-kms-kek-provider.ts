import { randomBytes, timingSafeEqual } from 'node:crypto';

import {
  isKeyCustodyError,
  KekUnavailableError,
  KeyDecryptionError,
  UnknownKekRefError,
} from '@qauth-labs/server-keys';
import {
  DATA_KEY_BYTES,
  type KekProvider,
  type KekProviderContext,
  type KekProviderHealth,
  type KekProviderModule,
  KEY_AAD_VERSION,
  type KeyAad,
  type WrappedDataKey,
} from '@qauth-labs/server-keys/custody';

import { encryptionContextOf } from './encryption-context';
import { kmsErrorName, toKeyCustodyError } from './errors';
import { formatKekRef, parseKekRef } from './kek-ref';
import { createKmsClient, type KmsOperations, kmsOperationsOf } from './kms-client';
import { AWS_KMS_KEK_PROVIDER, readAwsKmsSettings } from './settings';

/** What {@link createAwsKmsKekProvider} needs. */
export interface AwsKmsKekProviderOptions {
  /** The key ARN of the symmetric encryption KMS key that is the KEK. */
  readonly keyArn: string;
  /** The KMS operations: an SDK client's, or a test double's. */
  readonly kms: KmsOperations;
}

/** The largest ciphertext KMS Decrypt accepts, in bytes. */
const MAX_CIPHERTEXT_BYTES = 6144;

/** KMS's only algorithm for a symmetric encryption key: AES-256-GCM inside KMS. */
const ALGORITHM = 'SYMMETRIC_DEFAULT';

/**
 * The associated data {@link KekProvider.health} wraps a random probe under.
 * It has the same encryption-context keys as a stored key's, so a key policy
 * that requires them lets the probe through.
 */
const HEALTH_AAD: KeyAad = Object.freeze({
  realmId: 'qauth-kek-health',
  purpose: 'kek_health',
  scopeId: null,
  kid: 'kek-health',
  algorithm: 'A256GCM',
  version: KEY_AAD_VERSION,
});

/** Run a KMS call, reporting its failure as a key-custody error. */
async function kmsCall<T>(call: () => Promise<T>): Promise<T> {
  try {
    return await call();
  } catch (error) {
    throw toKeyCustodyError(error);
  }
}

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

/** Why {@link KekProvider.health} fails: a code and an exception type, never a secret. */
function healthReason(error: unknown): string {
  if (!isKeyCustodyError(error)) return 'The KMS call failed unexpectedly';
  const kmsError = kmsErrorName(error.cause);
  return kmsError === undefined
    ? `${error.code}: ${error.message}`
    : `${error.code}: ${error.message} (${kmsError})`;
}

/**
 * The AWS KMS KEK provider (ADR-019 Decision 9, #577): the KEK is a symmetric
 * encryption key in AWS KMS, and it never leaves KMS.
 *
 * - `wrap` sends the data key to KMS Encrypt under the key ARN, with the key's
 *   associated data as the encryption context (`encryption-context.ts`). It
 *   then decrypts the result once, which proves that this role can open what
 *   it stores, before anything is stored, and tells which key material
 *   wrapped it: Encrypt does not say, Decrypt does. `kekRef` is
 *   `<key ARN>#<key material ID>` (`kek-ref.ts`).
 * - `unwrap` refuses a `kekRef` that names another key ARN, without a call,
 *   then sends the ciphertext to KMS Decrypt under the key ARN and the
 *   encryption context, and checks that the result is a data key. The SDK's
 *   copy of the plaintext is zeroed; the caller gets its own.
 * - `health` wraps and unwraps a random probe.
 *
 * Signing stays in the signer: KMS only wraps data keys, because its support
 * for EdDSA and ML-DSA varies. Every KMS failure is a typed error
 * (`errors.ts`), after the KMS client's bounded retries (`kms-client.ts`).
 */
export function createAwsKmsKekProvider(options: AwsKmsKekProviderOptions): KekProvider {
  const { keyArn, kms } = options;

  /** Decrypt `wrapped` under the KEK and `context`: a data key the caller owns. */
  async function decryptDataKey(
    wrapped: Uint8Array,
    context: Record<string, string>
  ): Promise<{ readonly dek: Buffer; readonly keyMaterialId: string | undefined }> {
    const answer = await kmsCall(() =>
      kms.decrypt({
        CiphertextBlob: wrapped,
        KeyId: keyArn,
        EncryptionContext: context,
        EncryptionAlgorithm: ALGORITHM,
      })
    );
    const plaintext = answer.Plaintext;
    if (plaintext === undefined) {
      throw new KekUnavailableError({ cause: new Error('KMS Decrypt returned no plaintext') });
    }
    const dek = Buffer.from(plaintext);
    plaintext.fill(0);
    if (dek.length !== DATA_KEY_BYTES) {
      dek.fill(0);
      throw new KeyDecryptionError({ detail: 'the wrapped value is not a data key' });
    }
    return { dek, keyMaterialId: answer.KeyMaterialId };
  }

  async function wrap(dek: Uint8Array, aad: KeyAad): Promise<WrappedDataKey> {
    if (dek.length !== DATA_KEY_BYTES) {
      throw new RangeError(`A data key must be ${DATA_KEY_BYTES} bytes`);
    }
    const context = encryptionContextOf(aad);
    const answer = await kmsCall(() =>
      kms.encrypt({
        KeyId: keyArn,
        Plaintext: dek,
        EncryptionContext: context,
        EncryptionAlgorithm: ALGORITHM,
      })
    );
    if (answer.CiphertextBlob === undefined || answer.CiphertextBlob.length === 0) {
      throw new KekUnavailableError({ cause: new Error('KMS Encrypt returned no ciphertext') });
    }
    const wrapped = Buffer.from(answer.CiphertextBlob);

    const opened = await decryptDataKey(wrapped, context);
    try {
      if (!sameBytes(opened.dek, dek)) {
        throw new KeyDecryptionError({ detail: 'the wrapped data key opened to other bytes' });
      }
    } finally {
      opened.dek.fill(0);
    }
    return Object.freeze({ wrapped, kekRef: formatKekRef(keyArn, opened.keyMaterialId) });
  }

  return Object.freeze({
    name: AWS_KMS_KEK_PROVIDER,

    wrap,

    async unwrap(wrapped: Uint8Array, aad: KeyAad, kekRef: string): Promise<Uint8Array> {
      if (parseKekRef(kekRef).keyArn !== keyArn) throw new UnknownKekRefError(kekRef);

      let context: Record<string, string>;
      try {
        context = encryptionContextOf(aad);
      } catch (error) {
        throw new KeyDecryptionError({ detail: 'unusable associated data', cause: error });
      }
      if (wrapped.length === 0 || wrapped.length > MAX_CIPHERTEXT_BYTES) {
        throw new KeyDecryptionError({ detail: 'malformed wrapped data key' });
      }
      return (await decryptDataKey(wrapped, context)).dek;
    },

    async health(): Promise<KekProviderHealth> {
      const probe = randomBytes(DATA_KEY_BYTES);
      try {
        const { kekRef } = await wrap(probe, HEALTH_AAD);
        return Object.freeze({ ok: true, provider: AWS_KMS_KEK_PROVIDER, kekRef });
      } catch (error) {
        return Object.freeze({
          ok: false,
          provider: AWS_KMS_KEK_PROVIDER,
          reason: healthReason(error),
        });
      } finally {
        probe.fill(0);
      }
    },
  });
}

/**
 * The adapter's entry point: `KEK_PROVIDER=aws-kms` makes the key library's
 * `loadKekProvider` import this package and call it.
 *
 * Reads `KEK_AWS_KMS_KEY_ID` and `KEK_AWS_REGION` (`settings.ts`) and creates
 * the KMS client. It makes no KMS call, so a KMS outage does not stop the
 * boot; the first wrap or unwrap reaches KMS.
 *
 * @throws InvalidConfigurationError when a setting is missing or invalid
 */
export const createKekProvider: KekProviderModule['createKekProvider'] = (
  context: KekProviderContext
) => {
  const settings = readAwsKmsSettings(context.env, context.warn);
  return createAwsKmsKekProvider({
    keyArn: settings.keyArn,
    kms: kmsOperationsOf(createKmsClient(settings.region)),
  });
};
