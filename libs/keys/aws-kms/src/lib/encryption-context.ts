import { encodeKeyAad, type KeyAad } from '@qauth-labs/server-keys/custody';

/**
 * The associated data of a stored key as a KMS encryption context (ADR-019
 * Decision 9, #577).
 *
 * KMS binds a ciphertext to the exact set of key and value pairs it was
 * encrypted under: Decrypt with any other set fails. Each field of the key's
 * associated data becomes one pair, so a wrapped data key copied to another
 * realm, purpose, scope, `kid` or algorithm does not open, as with the default
 * provider. Pairs rather than one encoded value, because CloudTrail logs the
 * context of every Encrypt and Decrypt, and a key policy can test a pair with
 * the `kms:EncryptionContext:<key>` condition key.
 *
 * | Key                 | Value                                    |
 * | ------------------- | ---------------------------------------- |
 * | `qauth:aad-version` | the associated-data format, such as `1`  |
 * | `qauth:realm-id`    | `realmId`                                |
 * | `qauth:purpose`     | `purpose`, such as `token_signing`       |
 * | `qauth:scope-id`    | `scopeId`; absent for an unscoped key    |
 * | `qauth:kid`         | `kid`                                    |
 * | `qauth:algorithm`   | `algorithm`, such as `EdDSA`             |
 *
 * The keys are fixed: stored keys open only while they stay the same, and
 * `encryption-context.test.ts` pins them.
 */
export const ENCRYPTION_CONTEXT_KEYS = Object.freeze({
  version: 'qauth:aad-version',
  realmId: 'qauth:realm-id',
  purpose: 'qauth:purpose',
  scopeId: 'qauth:scope-id',
  kid: 'qauth:kid',
  algorithm: 'qauth:algorithm',
});

/**
 * The encryption context for `aad`.
 *
 * The fields are checked as the default provider checks them, so a value the
 * associated-data format refuses, such as an empty string, is refused here too.
 * A present `scopeId` is never empty, so leaving the pair out for `null` cannot
 * be confused with a scope.
 *
 * @throws TypeError when a field is empty, not a string, or not well-formed
 * @throws RangeError when the version is not a supported format
 */
export function encryptionContextOf(aad: KeyAad): Record<string, string> {
  encodeKeyAad(aad);
  const context: Record<string, string> = {
    [ENCRYPTION_CONTEXT_KEYS.version]: String(aad.version),
    [ENCRYPTION_CONTEXT_KEYS.realmId]: aad.realmId,
    [ENCRYPTION_CONTEXT_KEYS.purpose]: aad.purpose,
    [ENCRYPTION_CONTEXT_KEYS.kid]: aad.kid,
    [ENCRYPTION_CONTEXT_KEYS.algorithm]: aad.algorithm,
  };
  if (aad.scopeId !== null) context[ENCRYPTION_CONTEXT_KEYS.scopeId] = aad.scopeId;
  return context;
}
