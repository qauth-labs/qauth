import { encodeKeyAad, type KeyAad } from '@qauth-labs/server-keys/custody';

import { isKeyVersion } from './kek-ref';

/**
 * What the provider sends to the Transit engine and keeps of its answers
 * (ADR-019 Decision 9, #578).
 *
 * **The context.** A stored key's associated data is the Transit `context`:
 * the same canonical encoding the default provider authenticates as AES-GCM
 * associated data (`encodeKeyAad`), in base64. On a key created with
 * `derived=true`, Vault derives a separate encryption key from each context,
 * so a wrapped data key copied to another realm, purpose, scope, `kid` or
 * algorithm does not open. Vault ignores the context of a key that is not
 * derived, which would drop that binding without an error; the provider
 * therefore refuses such a key (`vault-kek-provider.ts`).
 *
 * **The ciphertext.** Vault answers `vault:v<version>:<base64>`. The stored
 * `wrapped_dek` is the decoded bytes alone, and the version goes to `kekRef`,
 * so the row holds each fact once; unwrapping rebuilds the string from both.
 */

/** The Transit `context` for `aad`: its canonical encoding, in base64. */
export function transitContextOf(aad: KeyAad): string {
  return encodeKeyAad(aad).toString('base64');
}

/** Vault's ciphertext for `bytes` under key version `version`. */
export function formatCiphertext(version: number, bytes: Uint8Array): string {
  return `vault:v${version}:${Buffer.from(bytes).toString('base64')}`;
}

/** Vault's ciphertext format. */
const CIPHERTEXT =
  /^vault:v([1-9][0-9]{0,9}):((?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)$/;

/** What a Vault ciphertext holds. */
export interface ParsedCiphertext {
  readonly version: number;
  readonly bytes: Buffer;
}

/**
 * Split a Vault ciphertext into its key version and bytes, or `undefined` for
 * a value that is not one: another prefix, an empty body, or base64 that does
 * not decode to the same text.
 */
export function parseCiphertext(text: unknown): ParsedCiphertext | undefined {
  if (typeof text !== 'string') return undefined;
  const match = CIPHERTEXT.exec(text);
  if (match === null || match[2] === '') return undefined;
  const version = Number(match[1]);
  if (!isKeyVersion(version)) return undefined;
  const bytes = Buffer.from(match[2], 'base64');
  if (bytes.toString('base64') !== match[2]) return undefined;
  return { version, bytes };
}
