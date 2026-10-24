import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

import {
  type DecryptCommandInput,
  type DecryptCommandOutput,
  DisabledException,
  type EncryptCommandInput,
  type EncryptCommandOutput,
  IncorrectKeyException,
  InvalidCiphertextException,
  KMSServiceException,
  NotFoundException,
} from '@aws-sdk/client-kms';

import type { KmsOperations } from '../lib/kms-client';

/**
 * A KMS test double: symmetric encryption keys held in memory, with the
 * Encrypt and Decrypt behaviour the provider relies on (ADR-019 Decision 9,
 * #577).
 *
 * - A ciphertext names its key ARN and key material, and is AES-256-GCM over
 *   the plaintext with the encryption context authenticated, so Decrypt under
 *   another context, a tampered ciphertext or another key's ARN fails with
 *   the exception KMS raises.
 * - A key rotates to new key material; the old material still decrypts, as in
 *   KMS. Encrypt does not report the key material and Decrypt does, as in KMS.
 * - Errors are the SDK's own exception classes, so the error mapping is
 *   tested against what the client throws.
 *
 * It never leaves the process. `kms-client.test.ts` serves it over HTTP to
 * the real SDK client.
 */

/** The key every test uses unless it adds another. */
export const DOUBLE_KEY_ARN =
  'arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

/** A second key in the same account. */
export const OTHER_KEY_ARN =
  'arn:aws:kms:eu-central-1:111122223333:key/0987dcba-09ba-87dc-65fe-0987654321ba';

/** A KMS service exception by name, such as `ThrottlingException`, which the SDK does not model. */
export function kmsError(name: string, fault: 'client' | 'server' = 'client'): KMSServiceException {
  return new KMSServiceException({
    name,
    $fault: fault,
    $metadata: { httpStatusCode: fault === 'client' ? 400 : 500 },
    message: `${name} from the KMS test double`,
  });
}

const FORMAT = 0x01;
const IV_BYTES = 12;
const TAG_BYTES = 16;

interface DoubleKey {
  readonly materials: Map<string, Buffer>;
  current: string;
  enabled: boolean;
}

/** One request the double received. */
export type KmsDoubleRequest =
  | { readonly operation: 'encrypt'; readonly input: EncryptCommandInput }
  | { readonly operation: 'decrypt'; readonly input: DecryptCommandInput };

export interface KmsDouble extends KmsOperations {
  /** Every request, in order. */
  readonly requests: KmsDoubleRequest[];
  /** Every plaintext Decrypt returned, to check that the caller zeroed it. */
  readonly returnedPlaintexts: Uint8Array[];
  /** Add a key. */
  addKey(keyArn: string): void;
  /** The key material Encrypt uses for `keyArn`. */
  currentKeyMaterialId(keyArn?: string): string;
  /** Give `keyArn` new key material. The old material still decrypts. */
  rotate(keyArn?: string): string;
  /** Disable or enable `keyArn`. */
  setEnabled(enabled: boolean, keyArn?: string): void;
  /** Make the next `times` calls of `operation` throw `error` instead. */
  failNext(operation: 'encrypt' | 'decrypt', error: Error, times?: number): void;
}

/** What {@link createKmsDouble} takes. */
export interface KmsDoubleOptions {
  /**
   * Whether Decrypt names the key material. KMS omits it for some keys, such
   * as one in a custom key store. Defaults to true.
   */
  readonly reportsKeyMaterial?: boolean;
}

/** The bytes GCM authenticates: the ciphertext header and the context, in key order. */
function authenticatedData(header: Buffer, context: Record<string, string> | undefined): Buffer {
  const pairs = Object.entries(context ?? {}).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return Buffer.concat([header, Buffer.from(JSON.stringify(pairs), 'utf8')]);
}

function header(keyArn: string, materialId: string): Buffer {
  const arn = Buffer.from(keyArn, 'utf8');
  const material = Buffer.from(materialId, 'utf8');
  const arnLength = Buffer.alloc(2);
  arnLength.writeUInt16BE(arn.length);
  return Buffer.concat([
    Buffer.from([FORMAT]),
    arnLength,
    arn,
    Buffer.from([material.length]),
    material,
  ]);
}

/** Split a ciphertext into its parts, or `undefined` when it is not one. */
function parse(blob: Uint8Array) {
  const bytes = Buffer.from(blob);
  if (bytes.length < 4 || bytes[0] !== FORMAT) return undefined;
  const arnEnd = 3 + bytes.readUInt16BE(1);
  if (bytes.length < arnEnd + 1) return undefined;
  const materialEnd = arnEnd + 1 + bytes[arnEnd];
  if (bytes.length < materialEnd + IV_BYTES + TAG_BYTES) return undefined;
  return {
    header: bytes.subarray(0, materialEnd),
    keyArn: bytes.subarray(3, arnEnd).toString('utf8'),
    materialId: bytes.subarray(arnEnd + 1, materialEnd).toString('utf8'),
    iv: bytes.subarray(materialEnd, materialEnd + IV_BYTES),
    body: bytes.subarray(materialEnd + IV_BYTES, bytes.length - TAG_BYTES),
    tag: bytes.subarray(bytes.length - TAG_BYTES),
  };
}

function newMaterialId(): string {
  return randomBytes(32).toString('hex');
}

/** A KMS test double holding {@link DOUBLE_KEY_ARN}. */
export function createKmsDouble(options: KmsDoubleOptions = {}): KmsDouble {
  const reportsKeyMaterial = options.reportsKeyMaterial ?? true;
  const keys = new Map<string, DoubleKey>();
  const failures: Array<{ operation: 'encrypt' | 'decrypt'; error: Error }> = [];
  const requests: KmsDoubleRequest[] = [];
  const returnedPlaintexts: Uint8Array[] = [];

  function addKey(keyArn: string): void {
    const materialId = newMaterialId();
    keys.set(keyArn, {
      materials: new Map([[materialId, randomBytes(32)]]),
      current: materialId,
      enabled: true,
    });
  }
  addKey(DOUBLE_KEY_ARN);

  function usableKey(keyArn: string | undefined): DoubleKey {
    const key = keyArn === undefined ? undefined : keys.get(keyArn);
    if (key === undefined) {
      throw new NotFoundException({
        message: 'Key not found in the KMS test double',
        $metadata: {},
      });
    }
    if (!key.enabled) {
      throw new DisabledException({ message: 'The key is disabled', $metadata: {} });
    }
    return key;
  }

  function injectedFailure(operation: 'encrypt' | 'decrypt'): void {
    const index = failures.findIndex((failure) => failure.operation === operation);
    if (index !== -1) throw failures.splice(index, 1)[0].error;
  }

  function checkAlgorithm(algorithm: string | undefined): void {
    if (algorithm !== undefined && algorithm !== 'SYMMETRIC_DEFAULT') {
      throw kmsError('ValidationException');
    }
  }

  const invalidCiphertext = () =>
    new InvalidCiphertextException({ message: 'The ciphertext is invalid', $metadata: {} });

  return {
    requests,
    returnedPlaintexts,
    addKey,

    currentKeyMaterialId(keyArn = DOUBLE_KEY_ARN) {
      return usableKey(keyArn).current;
    },

    rotate(keyArn = DOUBLE_KEY_ARN) {
      const key = usableKey(keyArn);
      const materialId = newMaterialId();
      key.materials.set(materialId, randomBytes(32));
      key.current = materialId;
      return materialId;
    },

    setEnabled(enabled, keyArn = DOUBLE_KEY_ARN) {
      const key = keys.get(keyArn);
      if (key !== undefined) key.enabled = enabled;
    },

    failNext(operation, error, times = 1) {
      for (let i = 0; i < times; i++) failures.push({ operation, error });
    },

    async encrypt(input: EncryptCommandInput): Promise<EncryptCommandOutput> {
      requests.push({ operation: 'encrypt', input });
      injectedFailure('encrypt');
      const key = usableKey(input.KeyId);
      checkAlgorithm(input.EncryptionAlgorithm);
      const plaintext = input.Plaintext;
      if (plaintext === undefined || plaintext.length === 0 || plaintext.length > 4096) {
        throw kmsError('ValidationException');
      }
      const head = header(input.KeyId as string, key.current);
      const iv = randomBytes(IV_BYTES);
      const cipher = createCipheriv('aes-256-gcm', key.materials.get(key.current) as Buffer, iv);
      cipher.setAAD(authenticatedData(head, input.EncryptionContext));
      const body = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      return {
        CiphertextBlob: new Uint8Array(Buffer.concat([head, iv, body, cipher.getAuthTag()])),
        KeyId: input.KeyId,
        EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
        $metadata: {},
      };
    },

    async decrypt(input: DecryptCommandInput): Promise<DecryptCommandOutput> {
      requests.push({ operation: 'decrypt', input });
      injectedFailure('decrypt');
      checkAlgorithm(input.EncryptionAlgorithm);
      const parts = input.CiphertextBlob === undefined ? undefined : parse(input.CiphertextBlob);
      if (parts === undefined) throw invalidCiphertext();
      if (input.KeyId !== undefined && input.KeyId !== parts.keyArn) {
        throw new IncorrectKeyException({
          message: 'The ciphertext was not encrypted under the key in the request',
          $metadata: {},
        });
      }
      const key = usableKey(parts.keyArn);
      const material = key.materials.get(parts.materialId);
      if (material === undefined) throw invalidCiphertext();
      const decipher = createDecipheriv('aes-256-gcm', material, parts.iv);
      decipher.setAAD(authenticatedData(parts.header, input.EncryptionContext));
      decipher.setAuthTag(parts.tag);
      let plaintext: Uint8Array;
      try {
        plaintext = new Uint8Array(Buffer.concat([decipher.update(parts.body), decipher.final()]));
      } catch {
        throw invalidCiphertext();
      }
      returnedPlaintexts.push(plaintext);
      return {
        Plaintext: plaintext,
        KeyId: parts.keyArn,
        EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
        ...(reportsKeyMaterial ? { KeyMaterialId: parts.materialId } : {}),
        $metadata: {},
      };
    },
  };
}
