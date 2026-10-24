import { randomBytes } from 'node:crypto';

import { isKeyCustodyError, type KeyCustodyErrorCode } from '@qauth-labs/server-keys';
import {
  KEY_AAD_VERSION,
  type KeyAad,
  runKekProviderContract,
} from '@qauth-labs/server-keys/custody';
import { describe, expect, it } from 'vitest';

import { createKmsDouble, DOUBLE_KEY_ARN, kmsError, OTHER_KEY_ARN } from '../testing/kms-double';
import { createAwsKmsKekProvider } from './aws-kms-kek-provider';
import { ENCRYPTION_CONTEXT_KEYS } from './encryption-context';

const AAD: KeyAad = Object.freeze({
  realmId: '0b6f4d1e-2c3a-4f5b-8e9d-0a1b2c3d4e5f',
  purpose: 'token_signing',
  scopeId: null,
  kid: 'kid-1',
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
});

const CONTEXT = {
  'qauth:aad-version': '1',
  'qauth:realm-id': AAD.realmId,
  'qauth:purpose': 'token_signing',
  'qauth:kid': 'kid-1',
  'qauth:algorithm': 'EdDSA',
};

function provider(kms = createKmsDouble()) {
  return { kms, kek: createAwsKmsKekProvider({ keyArn: DOUBLE_KEY_ARN, kms }) };
}

/** The key-custody error a promise rejects with. */
async function custodyError(promise: Promise<unknown>, code: KeyCustodyErrorCode) {
  const error = await promise.then(
    () => undefined,
    (reason: unknown) => reason
  );
  expect(isKeyCustodyError(error, code), `expected ${code}, got ${String(error)}`).toBe(true);
  return error as Error & { cause?: unknown; detail?: string };
}

// One KMS for every instance the kit creates, as a restarted signer reaches the
// same KMS key.
const contractKms = createKmsDouble();
runKekProviderContract({
  name: 'aws-kms (KMS test double)',
  createProvider: () => createAwsKmsKekProvider({ keyArn: DOUBLE_KEY_ARN, kms: contractKms }),
  describe,
  it,
});

describe('wrap', () => {
  it('sends the data key to Encrypt under the key ARN, with the associated data as the encryption context', async () => {
    const { kms, kek } = provider();
    const dek = randomBytes(32);

    await kek.wrap(dek, AAD);

    expect(kms.requests[0]).toEqual({
      operation: 'encrypt',
      input: {
        KeyId: DOUBLE_KEY_ARN,
        Plaintext: dek,
        EncryptionContext: CONTEXT,
        EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
      },
    });
  });

  it('decrypts what Encrypt returned before handing it back, and zeroes that plaintext', async () => {
    const { kms, kek } = provider();

    const { wrapped } = await kek.wrap(randomBytes(32), AAD);

    expect(kms.requests.map((request) => request.operation)).toEqual(['encrypt', 'decrypt']);
    expect(kms.requests[1].input).toEqual({
      CiphertextBlob: wrapped,
      KeyId: DOUBLE_KEY_ARN,
      EncryptionContext: CONTEXT,
      EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
    });
    expect(Buffer.from(kms.returnedPlaintexts[0]).equals(Buffer.alloc(32))).toBe(true);
  });

  it('names the key ARN and the key material that wrapped it in kekRef', async () => {
    const { kms, kek } = provider();

    const { kekRef } = await kek.wrap(randomBytes(32), AAD);

    expect(kekRef).toBe(`${DOUBLE_KEY_ARN}#${kms.currentKeyMaterialId()}`);
  });

  it('after KMS rotates the key, names the new key material and still opens rows wrapped before', async () => {
    const { kms, kek } = provider();
    const dek = randomBytes(32);
    const before = await kek.wrap(Buffer.from(dek), AAD);

    const rotated = kms.rotate();
    const after = await kek.wrap(randomBytes(32), AAD);

    expect(after.kekRef).toBe(`${DOUBLE_KEY_ARN}#${rotated}`);
    expect(after.kekRef).not.toBe(before.kekRef);
    expect(Buffer.from(await kek.unwrap(before.wrapped, AAD, before.kekRef))).toEqual(dek);
  });

  it('names the key ARN alone when KMS reports no key material', async () => {
    const { kek } = provider(createKmsDouble({ reportsKeyMaterial: false }));

    const { wrapped, kekRef } = await kek.wrap(randomBytes(32), AAD);

    expect(kekRef).toBe(DOUBLE_KEY_ARN);
    expect((await kek.unwrap(wrapped, AAD, kekRef)).length).toBe(32);
  });

  it('refuses to hand back a data key this role cannot decrypt, so it is never stored', async () => {
    const { kms, kek } = provider();
    kms.failNext('decrypt', kmsError('AccessDeniedException'));

    const error = await custodyError(kek.wrap(randomBytes(32), AAD), 'KEK_ACCESS_DENIED');

    expect((error.cause as Error).name).toBe('AccessDeniedException');
  });

  it('refuses a ciphertext that does not open back to the data key it was given', async () => {
    const kms = createKmsDouble();
    const kek = createAwsKmsKekProvider({
      keyArn: DOUBLE_KEY_ARN,
      kms: {
        encrypt: (input) => kms.encrypt(input),
        decrypt: async (input) => ({ ...(await kms.decrypt(input)), Plaintext: randomBytes(32) }),
      },
    });

    const error = await custodyError(kek.wrap(randomBytes(32), AAD), 'KEY_DECRYPTION_FAILED');

    expect(error.detail).toBe('the wrapped data key opened to other bytes');
  });

  it('refuses a data key that is not 32 bytes, without a KMS call', async () => {
    const { kms, kek } = provider();

    await expect(kek.wrap(randomBytes(16), AAD)).rejects.toThrow(RangeError);
    expect(kms.requests).toEqual([]);
  });

  it('refuses associated data the format refuses, without a KMS call', async () => {
    const { kms, kek } = provider();

    await expect(kek.wrap(randomBytes(32), { ...AAD, kid: '' })).rejects.toThrow(TypeError);
    expect(kms.requests).toEqual([]);
  });
});

describe('unwrap', () => {
  it('decrypts under the key ARN and the encryption context of the associated data', async () => {
    const { kms, kek } = provider();
    const scoped: KeyAad = { ...AAD, purpose: 'webhook_signing', scopeId: 'subscription-1' };
    const { wrapped, kekRef } = await kek.wrap(randomBytes(32), scoped);
    kms.requests.length = 0;

    await kek.unwrap(wrapped, scoped, kekRef);

    expect(kms.requests).toEqual([
      {
        operation: 'decrypt',
        input: {
          CiphertextBlob: wrapped,
          KeyId: DOUBLE_KEY_ARN,
          EncryptionContext: {
            ...CONTEXT,
            'qauth:purpose': 'webhook_signing',
            'qauth:scope-id': 'subscription-1',
          },
          EncryptionAlgorithm: 'SYMMETRIC_DEFAULT',
        },
      },
    ]);
  });

  it('fails under a wrong encryption context: KMS refuses the ciphertext', async () => {
    const { kms, kek } = provider();
    const { wrapped, kekRef } = await kek.wrap(randomBytes(32), AAD);

    // KMS itself refuses another context.
    await expect(
      kms.decrypt({
        CiphertextBlob: wrapped,
        KeyId: DOUBLE_KEY_ARN,
        EncryptionContext: { ...CONTEXT, [ENCRYPTION_CONTEXT_KEYS.realmId]: 'another-realm' },
      })
    ).rejects.toMatchObject({ name: 'InvalidCiphertextException' });
    await expect(
      kms.decrypt({ CiphertextBlob: wrapped, KeyId: DOUBLE_KEY_ARN, EncryptionContext: {} })
    ).rejects.toMatchObject({ name: 'InvalidCiphertextException' });

    // And the provider reports it as a key that does not open.
    const error = await custodyError(
      kek.unwrap(wrapped, { ...AAD, kid: 'kid-2' }, kekRef),
      'KEY_DECRYPTION_FAILED'
    );
    expect((error.cause as Error).name).toBe('InvalidCiphertextException');
  });

  it('refuses a kekRef that names another key, without a KMS call', async () => {
    const { kms, kek } = provider();
    const { wrapped } = await kek.wrap(randomBytes(32), AAD);
    kms.requests.length = 0;

    for (const kekRef of [OTHER_KEY_ARN, `${OTHER_KEY_ARN}#material`, '0123456789abcdef', '']) {
      const error = await custodyError(kek.unwrap(wrapped, AAD, kekRef), 'KEK_UNKNOWN_REF');
      expect(error).toMatchObject({ kekRef });
    }
    expect(kms.requests).toEqual([]);
  });

  it('opens a row whose kekRef names the key ARN without the key material', async () => {
    const { kek } = provider();
    const dek = randomBytes(32);
    const { wrapped } = await kek.wrap(Buffer.from(dek), AAD);

    expect(Buffer.from(await kek.unwrap(wrapped, AAD, DOUBLE_KEY_ARN))).toEqual(dek);
  });

  it("refuses another key's ciphertext under this key's kekRef", async () => {
    const kms = createKmsDouble();
    kms.addKey(OTHER_KEY_ARN);
    const other = createAwsKmsKekProvider({ keyArn: OTHER_KEY_ARN, kms });
    const { kek } = provider(kms);
    const { wrapped } = await other.wrap(randomBytes(32), AAD);

    const error = await custodyError(
      kek.unwrap(wrapped, AAD, DOUBLE_KEY_ARN),
      'KEY_DECRYPTION_FAILED'
    );
    expect((error.cause as Error).name).toBe('IncorrectKeyException');
  });

  it('zeroes the plaintext KMS returned and gives the caller its own copy', async () => {
    const { kms, kek } = provider();
    const dek = randomBytes(32);
    const { wrapped, kekRef } = await kek.wrap(Buffer.from(dek), AAD);

    const opened = await kek.unwrap(wrapped, AAD, kekRef);

    const fromKms = kms.returnedPlaintexts[kms.returnedPlaintexts.length - 1];
    expect(Buffer.from(fromKms).equals(Buffer.alloc(32))).toBe(true);
    expect(Buffer.from(opened)).toEqual(dek);
  });

  it('refuses a ciphertext that opens to something other than a data key, and zeroes it', async () => {
    const { kms, kek } = provider();
    const encrypted = await kms.encrypt({
      KeyId: DOUBLE_KEY_ARN,
      Plaintext: randomBytes(16),
      EncryptionContext: CONTEXT,
    });

    const error = await custodyError(
      kek.unwrap(encrypted.CiphertextBlob as Uint8Array, AAD, DOUBLE_KEY_ARN),
      'KEY_DECRYPTION_FAILED'
    );

    expect(error.detail).toBe('the wrapped value is not a data key');
    expect(Buffer.from(kms.returnedPlaintexts[0]).equals(Buffer.alloc(16))).toBe(true);
  });

  it('refuses an empty or oversized ciphertext, and unusable associated data, without a KMS call', async () => {
    const { kms, kek } = provider();

    await custodyError(kek.unwrap(new Uint8Array(0), AAD, DOUBLE_KEY_ARN), 'KEY_DECRYPTION_FAILED');
    await custodyError(
      kek.unwrap(new Uint8Array(6145), AAD, DOUBLE_KEY_ARN),
      'KEY_DECRYPTION_FAILED'
    );
    await custodyError(
      kek.unwrap(new Uint8Array(64), { ...AAD, version: 99 }, DOUBLE_KEY_ARN),
      'KEY_DECRYPTION_FAILED'
    );
    expect(kms.requests).toEqual([]);
  });
});

describe('KMS failures', () => {
  it.each<[string, Error, KeyCustodyErrorCode]>([
    ['throttling', kmsError('ThrottlingException'), 'KEK_UNAVAILABLE'],
    ['a KMS internal error', kmsError('KMSInternalException', 'server'), 'KEK_UNAVAILABLE'],
    ['an unavailable key store', kmsError('KeyUnavailableException', 'server'), 'KEK_UNAVAILABLE'],
    [
      'a refused connection',
      Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }),
      'KEK_UNAVAILABLE',
    ],
    ['a policy that denies the call', kmsError('AccessDeniedException'), 'KEK_ACCESS_DENIED'],
    ['a disabled key', kmsError('DisabledException'), 'KEK_ACCESS_DENIED'],
    [
      'missing credentials',
      Object.assign(new Error('Could not load credentials'), { name: 'CredentialsProviderError' }),
      'KEK_ACCESS_DENIED',
    ],
  ])(
    'reports %s on wrap and unwrap as %s, keeping the KMS error as the cause',
    async (_what, kmsFailure, code) => {
      const { kms, kek } = provider();
      const { wrapped, kekRef } = await kek.wrap(randomBytes(32), AAD);

      kms.failNext('encrypt', kmsFailure);
      expect((await custodyError(kek.wrap(randomBytes(32), AAD), code)).cause).toBe(kmsFailure);
      kms.failNext('decrypt', kmsFailure);
      expect((await custodyError(kek.unwrap(wrapped, AAD, kekRef), code)).cause).toBe(kmsFailure);
    }
  );

  it('marks an outage as retryable', async () => {
    const { kms, kek } = provider();
    kms.failNext('encrypt', kmsError('ThrottlingException'));

    expect(await custodyError(kek.wrap(randomBytes(32), AAD), 'KEK_UNAVAILABLE')).toMatchObject({
      retryable: true,
    });
  });
});

describe('health', () => {
  it('wraps and unwraps a probe, and names the kekRef wrap returns', async () => {
    const { kms, kek } = provider();

    const health = await kek.health();

    expect(health).toEqual({
      ok: true,
      provider: 'aws-kms',
      kekRef: `${DOUBLE_KEY_ARN}#${kms.currentKeyMaterialId()}`,
    });
    // The probe carries the same encryption-context keys as a stored key.
    const probe = kms.requests[0];
    expect(Object.keys(probe.input.EncryptionContext ?? {}).sort()).toEqual(
      Object.keys(CONTEXT).sort()
    );
  });

  it('reports a failure with its code and the KMS exception, and never throws', async () => {
    const { kms, kek } = provider();
    kms.setEnabled(false);

    expect(await kek.health()).toEqual({
      ok: false,
      provider: 'aws-kms',
      reason:
        'KEK_ACCESS_DENIED: The key-encryption key provider denied access (DisabledException)',
    });
  });
});
