/**
 * The associated data that binds sealed key material to the row it belongs to
 * (ADR-019 Decision 9).
 *
 * Both AES-256-GCM operations of the envelope, the material under its data key
 * and the data key under the KEK, authenticate these bytes. A row copied to
 * another realm, purpose, scope, `kid` or algorithm therefore fails to open:
 * its stored ciphertext was sealed with different associated data.
 */

/** The columns of a stored key that name it. `realm_keys` holds each one. */
export interface KeyIdentity {
  /** The realm the key belongs to. */
  readonly realmId: string;
  /** The key purpose, such as `token_signing`. */
  readonly purpose: string;
  /**
   * The scope inside the purpose, such as a webhook subscription. `null` for
   * an unscoped purpose. An empty string is refused, so it cannot stand in
   * for `null`.
   */
  readonly scopeId: string | null;
  /** The key id, unique within the realm. */
  readonly kid: string;
  /** The key's algorithm, such as `EdDSA`. */
  readonly algorithm: string;
}

/** A {@link KeyIdentity} with the version of the associated-data format. */
export interface KeyAad extends KeyIdentity {
  /** The `aad_version` the row stores. See {@link KEY_AAD_VERSION}. */
  readonly version: number;
}

/**
 * The associated-data format new key material is sealed with. A row stores it
 * as `aad_version`, so a later format can be added without re-sealing old rows.
 */
export const KEY_AAD_VERSION = 1;

/** Every format {@link encodeKeyAad} can write. */
export const SUPPORTED_KEY_AAD_VERSIONS: readonly number[] = [KEY_AAD_VERSION];

/** Domain separation: these bytes start every encoding and no other QAuth input. */
const LABEL = Buffer.from('qauth/key-aad', 'ascii');

const ABSENT = 0x00;
const PRESENT = 0x01;

/** Encode one field as a presence byte, a 32-bit big-endian byte length and UTF-8. */
function field(name: string, value: string | null, nullable: boolean): Buffer {
  if (value === null) {
    if (!nullable) throw new TypeError(`Key associated data: ${name} must be a string`);
    return Buffer.from([ABSENT]);
  }
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`Key associated data: ${name} must be a non-empty string`);
  }
  const bytes = Buffer.from(value, 'utf8');
  // A lone surrogate would encode as U+FFFD, so two different values could
  // share one encoding. Refuse it instead.
  if (bytes.toString('utf8') !== value) {
    throw new TypeError(`Key associated data: ${name} must be well-formed Unicode`);
  }
  const length = Buffer.alloc(4);
  length.writeUInt32BE(bytes.length);
  return Buffer.concat([Buffer.from([PRESENT]), length, bytes]);
}

/**
 * The bytes AES-256-GCM authenticates for one stored key.
 *
 * Format 1, byte for byte:
 *
 * 1. the ASCII label `qauth/key-aad`;
 * 2. the version, one byte;
 * 3. `realmId`, `purpose`, `scopeId`, `kid` and `algorithm`, in that order. A
 *    field is `0x01`, its UTF-8 length as a 32-bit big-endian integer, then its
 *    UTF-8 bytes. An absent `scopeId` is the single byte `0x00`.
 *
 * Every field carries its length, so no two identities share an encoding. The
 * format is fixed: stored rows can only be opened while it stays the same, and
 * `aad.test.ts` pins it with a test vector.
 *
 * @throws TypeError when a field is empty, not a string, or not well-formed
 * @throws RangeError when the version is not in {@link SUPPORTED_KEY_AAD_VERSIONS}
 */
export function encodeKeyAad(aad: KeyAad): Buffer {
  if (!SUPPORTED_KEY_AAD_VERSIONS.includes(aad.version)) {
    throw new RangeError('Key associated data: unsupported version');
  }
  return Buffer.concat([
    LABEL,
    Buffer.from([aad.version]),
    field('realmId', aad.realmId, false),
    field('purpose', aad.purpose, false),
    field('scopeId', aad.scopeId, true),
    field('kid', aad.kid, false),
    field('algorithm', aad.algorithm, false),
  ]);
}

/**
 * Copy exactly the associated-data fields out of `identity`, with `version`.
 *
 * A caller may pass a whole stored row as the identity. Only these six fields
 * reach a provider, so an adapter never sees a column it was not meant to.
 */
export function keyAad(identity: KeyIdentity, version: number): KeyAad {
  return Object.freeze({
    realmId: identity.realmId,
    purpose: identity.purpose,
    scopeId: identity.scopeId,
    kid: identity.kid,
    algorithm: identity.algorithm,
    version,
  });
}
