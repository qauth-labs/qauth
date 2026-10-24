import { randomBytes } from 'node:crypto';

import { DecryptCommand, KMSClient } from '@aws-sdk/client-kms';
import { isKeyCustodyError } from '@qauth-labs/server-keys';
import {
  KEY_AAD_VERSION,
  type KeyAad,
  runKekProviderContract,
} from '@qauth-labs/server-keys/custody';
import { describe, expect, it } from 'vitest';

import { createKekProvider } from './aws-kms-kek-provider';
import { encryptionContextOf } from './encryption-context';
import { parseKekRef } from './kek-ref';
import { kmsClientConfig } from './kms-client';
import { readAwsKmsSettings } from './settings';

/**
 * The provider against a real KMS key (#577). Opt-in and manual: CI does not
 * run it, since it needs a key and credentials.
 *
 * ```console
 * KMS_TEST_KEY_ARN=<key ARN> pnpm exec nx run keys-aws-kms:test-kms
 * ```
 *
 * The key is a symmetric encryption key the caller may use for `kms:Encrypt`
 * and `kms:Decrypt`. Credentials come from the default AWS credential chain,
 * as in production: `AWS_PROFILE`, the `AWS_*` variables, or a role. Each run
 * makes a few dozen Encrypt and Decrypt calls and stores nothing.
 */

const keyArn = process.env['KMS_TEST_KEY_ARN']?.trim() ?? '';
const live = describe.skipIf(keyArn === '');

const AAD: KeyAad = Object.freeze({
  realmId: 'qauth-real-kms-test',
  purpose: 'token_signing',
  scopeId: null,
  kid: `kid-${randomBytes(4).toString('hex')}`,
  algorithm: 'EdDSA',
  version: KEY_AAD_VERSION,
});

function provider() {
  return createKekProvider({ env: { KEK_AWS_KMS_KEY_ID: keyArn }, warn: () => undefined });
}

runKekProviderContract({
  name: 'aws-kms (a real KMS key)',
  createProvider: provider,
  describe: live,
  it,
});

live('aws-kms against a real KMS key', () => {
  it('wraps and unwraps, naming the key ARN in kekRef', async () => {
    const kek = await provider();
    const dek = randomBytes(32);

    const { wrapped, kekRef } = await kek.wrap(Buffer.from(dek), AAD);

    expect(parseKekRef(kekRef).keyArn).toBe(keyArn);
    expect(Buffer.from(await kek.unwrap(wrapped, AAD, kekRef))).toEqual(dek);
  });

  it('cannot be decrypted under a wrong encryption context', async () => {
    const kek = await provider();
    const { wrapped, kekRef } = await kek.wrap(randomBytes(32), AAD);
    const client = new KMSClient(
      kmsClientConfig(readAwsKmsSettings({ KEK_AWS_KMS_KEY_ID: keyArn }, () => undefined).region)
    );

    try {
      await expect(
        client.send(
          new DecryptCommand({
            CiphertextBlob: wrapped,
            KeyId: keyArn,
            EncryptionContext: encryptionContextOf({ ...AAD, realmId: 'another-realm' }),
          })
        )
      ).rejects.toMatchObject({ name: 'InvalidCiphertextException' });
    } finally {
      client.destroy();
    }
    const error = await kek.unwrap(wrapped, { ...AAD, kid: 'another-kid' }, kekRef).then(
      () => undefined,
      (reason: unknown) => reason
    );
    expect(isKeyCustodyError(error, 'KEY_DECRYPTION_FAILED')).toBe(true);
  });

  it('reports itself healthy', async () => {
    expect(await (await provider()).health()).toMatchObject({ ok: true, provider: 'aws-kms' });
  });
});
