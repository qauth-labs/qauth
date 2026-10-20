import type { DecipherGCM } from 'node:crypto';

/**
 * Finish an AES-GCM decryption and return the plaintext.
 *
 * GCM hands out plaintext from `update()` before `final()` checks the tag. On
 * a failed check that unauthenticated plaintext is zeroed before the error
 * goes on. The result is the decipher's own output buffer, not a slice of
 * Node's shared buffer pool, so the caller can zero all of it.
 */
export function finishGcmDecryption(decipher: DecipherGCM, body: Uint8Array): Buffer {
  const plaintext = decipher.update(body);
  try {
    // GCM has no padding: `final()` adds no bytes and only checks the tag.
    decipher.final();
  } catch (error) {
    plaintext.fill(0);
    throw error;
  }
  return plaintext;
}
