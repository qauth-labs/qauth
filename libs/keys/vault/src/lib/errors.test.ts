import {
  isKeyCustodyError,
  KekUnavailableError,
  type KeyCustodyErrorCode,
} from '@qauth-labs/server-keys';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import {
  toKeyCustodyError,
  VaultAnswerError,
  VaultHttpError,
  VaultKeyRefusedError,
  type VaultOperation,
  VaultTransportError,
} from './errors';

const KEK_REF = 'vault:transit/keys/qauth-kek#v2';

function http(operation: VaultOperation, status: number, ...errors: string[]): VaultHttpError {
  return new VaultHttpError(operation, status, errors);
}

describe('how a failed Vault call maps onto the key-custody errors', () => {
  it.each<readonly [string, unknown, KeyCustodyErrorCode]>([
    [
      'a revoked or expired token',
      http('decrypt', 403, '* permission denied * invalid token'),
      'KEK_ACCESS_DENIED',
    ],
    ['a policy without the path', http('encrypt', 403, '* permission denied'), 'KEK_ACCESS_DENIED'],
    [
      'a refused AppRole login',
      http('approle-login', 400, 'invalid role or secret ID'),
      'KEK_ACCESS_DENIED',
    ],
    ['a missing key, read', http('read-key', 404), 'KEK_ACCESS_DENIED'],
    [
      'a missing key, decrypt',
      http('decrypt', 400, 'encryption key not found'),
      'KEK_ACCESS_DENIED',
    ],
    ['an unmounted path', http('decrypt', 404, 'no handler for route'), 'KEK_ACCESS_DENIED'],
    [
      'an unexpected refusal of encrypt',
      http('encrypt', 400, 'something else'),
      'KEK_ACCESS_DENIED',
    ],
    [
      'a refused renewal',
      http('token-renew-self', 400, 'lease is not renewable'),
      'KEK_ACCESS_DENIED',
    ],
    [
      'a failed authentication',
      http('decrypt', 400, 'cipher: message authentication failed'),
      'KEY_DECRYPTION_FAILED',
    ],
    [
      'a malformed ciphertext',
      http('decrypt', 400, 'invalid ciphertext length'),
      'KEY_DECRYPTION_FAILED',
    ],
    [
      'a version newer than the key',
      http('decrypt', 400, 'invalid ciphertext: version is too new'),
      'KEK_UNKNOWN_REF',
    ],
    [
      'a version below min_decryption_version',
      http('decrypt', 400, 'ciphertext or signature version is disallowed by policy (too old)'),
      'KEK_UNKNOWN_REF',
    ],
    ['a sealed Vault', http('decrypt', 503, 'Vault is sealed'), 'KEK_UNAVAILABLE'],
    ['throttling', http('encrypt', 429), 'KEK_UNAVAILABLE'],
    ['a performance standby that is not caught up', http('decrypt', 412), 'KEK_UNAVAILABLE'],
    ['a redirect', http('encrypt', 307), 'KEK_UNAVAILABLE'],
    [
      'no answer',
      new VaultTransportError('encrypt', Object.assign(new Error('x'), { code: 'ECONNREFUSED' })),
      'KEK_UNAVAILABLE',
    ],
    [
      'an untrusted certificate',
      new VaultTransportError(
        'encrypt',
        Object.assign(new Error('x'), { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' })
      ),
      'KEK_ACCESS_DENIED',
    ],
    [
      'an expired certificate',
      new VaultTransportError(
        'decrypt',
        Object.assign(new Error('x'), { code: 'CERT_HAS_EXPIRED' })
      ),
      'KEK_ACCESS_DENIED',
    ],
    [
      'a certificate for another host',
      new VaultTransportError(
        'decrypt',
        Object.assign(new Error('x'), { code: 'ERR_TLS_CERT_ALTNAME_INVALID' })
      ),
      'KEK_ACCESS_DENIED',
    ],
    [
      'an answer without its fields',
      new VaultAnswerError('encrypt', 'has no data'),
      'KEK_UNAVAILABLE',
    ],
    ['a key that is not derived', new VaultKeyRefusedError('not derived'), 'KEK_ACCESS_DENIED'],
    [
      'a token file that vanished',
      new InvalidConfigurationError('The file KEK_VAULT_TOKEN_FILE names does not exist.'),
      'KEK_ACCESS_DENIED',
    ],
    ['anything else', new Error('unexpected'), 'KEK_UNAVAILABLE'],
  ])('%s', (_what, error, code) => {
    const mapped = toKeyCustodyError(error, KEK_REF);

    expect(isKeyCustodyError(mapped, code)).toBe(true);
    if (code !== 'KEK_UNKNOWN_REF') expect(mapped.cause).toBe(error);
  });

  it('names the kekRef of a version Vault does not decrypt with', () => {
    expect(toKeyCustodyError(http('decrypt', 400, 'version is too new'), KEK_REF)).toMatchObject({
      code: 'KEK_UNKNOWN_REF',
      kekRef: KEK_REF,
    });
  });

  it('reads a version refusal outside decrypt, or without a kekRef, as no unknown kekRef', () => {
    expect(toKeyCustodyError(http('decrypt', 400, 'version is too new')).code).toBe(
      'KEY_DECRYPTION_FAILED'
    );
    expect(toKeyCustodyError(http('encrypt', 400, 'version is too new'), KEK_REF).code).toBe(
      'KEK_ACCESS_DENIED'
    );
  });

  it('passes a key-custody error through unchanged', () => {
    const error = new KekUnavailableError();

    expect(toKeyCustodyError(error)).toBe(error);
  });

  it("states the status, the operation and Vault's messages, and nothing a request carried", () => {
    expect(http('decrypt', 403, 'permission denied').message).toBe(
      'Vault answered 403 to decrypt: permission denied'
    );
    expect(http('read-key', 404).message).toBe('Vault answered 404 to read-key');
  });
});
