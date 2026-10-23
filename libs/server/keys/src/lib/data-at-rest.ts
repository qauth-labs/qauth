import { randomBytes } from 'node:crypto';

import { DataDecryptionError, SignerRequestRefusedError } from './signer-errors';

/**
 * The ciphertext format of the signer's `encrypt` and `decrypt`, for the
 * `data_at_rest` purpose (ADR-019 Decision 9, issue #464).
 *
 * A ciphertext is one ASCII string of four parts joined by `.`:
 *
 * 1. the version, `v1`;
 * 2. the `kid` of the `data_at_rest` key that encrypted it;
 * 3. the 96-bit AES-GCM nonce, base64url;
 * 4. the AES-256-GCM ciphertext followed by its 128-bit tag, base64url.
 *
 * The associated data is not stored. It is the ASCII label
 * `qauth/data-at-rest`, the version byte, then the realm id, the `kid` and the
 * caller's context, each as a 32-bit big-endian byte length and UTF-8. So a
 * ciphertext decrypts only in the realm, under the key and for the context it
 * was made for, and its `kid` cannot be swapped for another one.
 */
export const DATA_AT_REST_VERSION = 'v1';

/** The longest `context` the signer takes, in characters. */
export const MAX_DATA_CONTEXT_LENGTH = 1024;

/** A `kid` that fits the format: base64url, as the key factory makes them. */
const KID_PATTERN = /^[A-Za-z0-9_-]{1,255}$/;
const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;

const IV_BYTES = 12;
const TAG_BITS = 128;
const TAG_BYTES = TAG_BITS / 8;
const LABEL = Buffer.from('qauth/data-at-rest', 'ascii');
const VERSION_BYTE = 0x01;

/**
 * `bytes` as WebCrypto takes them. A buffer over a plain `ArrayBuffer`, which
 * is what Node allocates, passes as it is; anything else is copied.
 */
export function bufferSource(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  return bytes.buffer instanceof ArrayBuffer
    ? (bytes as Uint8Array<ArrayBuffer>)
    : new Uint8Array(bytes);
}

/** A parsed ciphertext. */
export interface DataEnvelope {
  readonly kid: string;
  readonly iv: Buffer;
  readonly body: Buffer;
}

/**
 * Check the caller's context and return it, `''` when absent.
 *
 * @throws SignerRequestRefusedError (`INVALID_CONTEXT`)
 */
export function resolveDataContext(context: unknown): string {
  if (context === undefined) return '';
  if (
    typeof context !== 'string' ||
    context.length > MAX_DATA_CONTEXT_LENGTH ||
    Buffer.from(context, 'utf8').toString('utf8') !== context
  ) {
    throw new SignerRequestRefusedError(
      'INVALID_CONTEXT',
      `A data context is a well-formed string of at most ${MAX_DATA_CONTEXT_LENGTH} characters`
    );
  }
  return context;
}

/** Whether `kid` can be written into a ciphertext. */
export function isDataKid(kid: string): boolean {
  return KID_PATTERN.test(kid);
}

function lengthPrefixed(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8');
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([length, bytes]);
}

/** The associated data of one ciphertext. */
export function dataAad(realmId: string, kid: string, context: string): Buffer {
  return Buffer.concat([
    LABEL,
    Buffer.from([VERSION_BYTE]),
    lengthPrefixed(realmId),
    lengthPrefixed(kid),
    lengthPrefixed(context),
  ]);
}

/** Encrypt `plaintext` under `key`, the AES-256-GCM key whose `kid` is `kid`. */
export async function sealData(
  key: CryptoKey,
  kid: string,
  realmId: string,
  context: string,
  plaintext: Uint8Array
): Promise<string> {
  const iv = randomBytes(IV_BYTES);
  const body = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: bufferSource(iv),
      additionalData: bufferSource(dataAad(realmId, kid, context)),
      tagLength: TAG_BITS,
    },
    key,
    bufferSource(plaintext)
  );
  return [
    DATA_AT_REST_VERSION,
    kid,
    iv.toString('base64url'),
    Buffer.from(body).toString('base64url'),
  ].join('.');
}

/**
 * Split a ciphertext into its parts. Reads nothing but the string.
 *
 * @throws DataDecryptionError when it is not a ciphertext of this format
 */
export function parseDataEnvelope(ciphertext: unknown): DataEnvelope {
  if (typeof ciphertext !== 'string') {
    throw new DataDecryptionError('not a string');
  }
  const parts = ciphertext.split('.');
  if (parts.length !== 4 || parts[0] !== DATA_AT_REST_VERSION) {
    throw new DataDecryptionError('not a v1 data-at-rest ciphertext');
  }
  const [, kid, ivText, bodyText] = parts;
  if (
    !KID_PATTERN.test(kid) ||
    !BASE64URL_PATTERN.test(ivText) ||
    !BASE64URL_PATTERN.test(bodyText)
  ) {
    throw new DataDecryptionError('malformed ciphertext');
  }
  const iv = Buffer.from(ivText, 'base64url');
  const body = Buffer.from(bodyText, 'base64url');
  if (iv.length !== IV_BYTES || body.length < TAG_BYTES) {
    throw new DataDecryptionError('malformed ciphertext');
  }
  return { kid, iv, body };
}

/**
 * Decrypt a parsed ciphertext with `key`.
 *
 * @throws DataDecryptionError when it does not authenticate
 */
export async function openData(
  key: CryptoKey,
  envelope: DataEnvelope,
  realmId: string,
  context: string
): Promise<Buffer> {
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: bufferSource(envelope.iv),
        additionalData: bufferSource(dataAad(realmId, envelope.kid, context)),
        tagLength: TAG_BITS,
      },
      key,
      bufferSource(envelope.body)
    );
    return Buffer.from(plaintext);
  } catch {
    throw new DataDecryptionError('ciphertext did not authenticate');
  }
}
