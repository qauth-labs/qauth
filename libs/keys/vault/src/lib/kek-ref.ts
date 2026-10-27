/**
 * The `kekRef` of a data key the Vault provider wrapped (ADR-019 Decision 9,
 * #578): the Transit key's API path and the key version that encrypted it,
 * `vault:<path>#v<version>`, for example `vault:transit/keys/qauth-kek#v3`.
 *
 * The path is `[<namespace>/]<mount>/keys/<name>`, the path an operator reads
 * the key at (`vault read transit/keys/qauth-kek`). Vault keeps every version
 * a rotation leaves behind for decryption, down to the key's
 * `min_decryption_version`, so the path decides which KEK opens a row, and the
 * version records which one wrapped it: a KEK rotation (#545) finds the rows
 * wrapped before Vault rotated the key and re-wraps them to the latest
 * version. The version is also the one part of Vault's ciphertext the stored
 * bytes leave out (`transit.ts`).
 *
 * The Vault address is deliberately not part of it: a performance replica or
 * a disaster-recovery secondary serves the same key under another address,
 * and the rows must keep opening after a failover. So two unrelated clusters
 * with the same namespace, mount and key name give the same `kekRef`; a row
 * from the wrong one fails to decrypt (`KEY_DECRYPTION_FAILED`).
 *
 * Both parts are identifiers, not secrets: safe to store and to log.
 */

const PREFIX = 'vault:';
const SEPARATOR = '#v';

/** A key version: a positive integer, as Vault numbers them. */
const VERSION = /^[1-9][0-9]{0,9}$/;
const MAX_VERSION = 2 ** 31 - 1;

/** What a `kekRef` names. */
export interface ParsedKekRef {
  /** The Transit key's path, such as `transit/keys/qauth-kek`. */
  readonly keyPath: string;
  /** The key version that wrapped the data key. */
  readonly version: number;
}

/** The path of the Transit key `name` on `mount`, under `namespace` when there is one. */
export function transitKeyPath(namespace: string | undefined, mount: string, name: string): string {
  return `${namespace === undefined ? '' : `${namespace}/`}${mount}/keys/${name}`;
}

/** Whether `version` is a key version a `kekRef` can hold. */
export function isKeyVersion(version: number): boolean {
  return Number.isSafeInteger(version) && version >= 1 && version <= MAX_VERSION;
}

/**
 * The `kekRef` of a data key wrapped by version `version` of the key at
 * `keyPath`.
 *
 * @throws RangeError when the version is not a positive integer
 */
export function formatKekRef(keyPath: string, version: number): string {
  if (!isKeyVersion(version)) throw new RangeError('A Transit key version is a positive integer');
  return `${PREFIX}${keyPath}${SEPARATOR}${version}`;
}

/** Split a `kekRef` into its key path and version, or `undefined` when it is not one of this provider's. */
export function parseKekRef(kekRef: string): ParsedKekRef | undefined {
  if (!kekRef.startsWith(PREFIX)) return undefined;
  const at = kekRef.lastIndexOf(SEPARATOR);
  if (at <= PREFIX.length) return undefined;
  const digits = kekRef.slice(at + SEPARATOR.length);
  if (!VERSION.test(digits)) return undefined;
  const version = Number(digits);
  if (!isKeyVersion(version)) return undefined;
  return { keyPath: kekRef.slice(PREFIX.length, at), version };
}
