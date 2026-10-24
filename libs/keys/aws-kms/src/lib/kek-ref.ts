/**
 * The `kekRef` of a data key the AWS KMS provider wrapped (ADR-019 Decision
 * 9, #577): the KMS key ARN and the key material that encrypted it,
 * `<key ARN>#<key material ID>`.
 *
 * A KMS key keeps every key material it rotated out for Decrypt, so the ARN
 * alone decides which KEK opens a row. The key material ID records which
 * material wrapped it, so a KEK rotation (#545) can find the rows wrapped
 * before KMS rotated the key and re-wrap them. Decrypt reads the material from
 * the ciphertext itself, so the ID is not needed to open a row. KMS reports no
 * key material for some keys, such as a key in a custom key store; the
 * `kekRef` is then the ARN alone.
 *
 * Both parts are identifiers, not secrets: safe to store and to log.
 */

const SEPARATOR = '#';

/** A key material ID as `kekRef` holds it: printable, without the separator. */
const KEY_MATERIAL_ID = /^[\x21-\x22\x24-\x7e]+$/;

/** What a `kekRef` names. */
export interface ParsedKekRef {
  readonly keyArn: string;
  readonly keyMaterialId: string | undefined;
}

/**
 * The `kekRef` of a data key wrapped under `keyArn` with `keyMaterialId`.
 *
 * @throws TypeError when the key material ID is empty, holds `#` or is not
 *   printable ASCII
 */
export function formatKekRef(keyArn: string, keyMaterialId: string | undefined): string {
  if (keyMaterialId === undefined) return keyArn;
  if (!KEY_MATERIAL_ID.test(keyMaterialId)) {
    throw new TypeError('A KMS key material ID must be printable ASCII without "#"');
  }
  return `${keyArn}${SEPARATOR}${keyMaterialId}`;
}

/** Split a `kekRef` into its key ARN and key material ID. */
export function parseKekRef(kekRef: string): ParsedKekRef {
  const at = kekRef.indexOf(SEPARATOR);
  if (at === -1) return { keyArn: kekRef, keyMaterialId: undefined };
  return { keyArn: kekRef.slice(0, at), keyMaterialId: kekRef.slice(at + 1) };
}
