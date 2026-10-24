import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  kekProviderPackage,
  type KekWarning,
  loadKekProvider,
} from '@qauth-labs/server-keys/custody';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import * as adapter from './index';

const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8')) as {
  name: string;
};

const ARN = 'arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

/**
 * The boot path: the signer's wiring calls the key library's `loadKekProvider`,
 * which imports `@qauth-labs/keys-<KEK_PROVIDER>` and calls its
 * `createKekProvider`. The import is replaced by this package's own entry
 * point, since the key library does not depend on it.
 */
function boot(env: Record<string, string>, warnings: KekWarning[] = []) {
  return loadKekProvider(
    { env: { NODE_ENV: 'production', ...env }, warn: (warning) => warnings.push(warning) },
    async (specifier) => {
      expect(specifier).toBe(packageJson.name);
      return adapter;
    }
  );
}

describe('the package as KEK_PROVIDER=aws-kms loads it', () => {
  it('is the package the key library imports for aws-kms', () => {
    expect(kekProviderPackage(adapter.AWS_KMS_KEK_PROVIDER)).toBe(packageJson.name);
    expect(packageJson.name).toBe('@qauth-labs/keys-aws-kms');
  });

  it('gives the loader a provider under its own name, without calling KMS', async () => {
    const provider = await boot({ KEK_PROVIDER: 'aws-kms', KEK_AWS_KMS_KEY_ID: ARN });

    expect(provider.name).toBe('aws-kms');
  });

  it('stops the boot with a clear message when KEK_AWS_KMS_KEY_ID is missing', async () => {
    const error = await boot({ KEK_PROVIDER: 'aws-kms' }).then(
      () => undefined,
      (reason: unknown) => reason
    );

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    expect((error as Error).message).toMatch(/^KEK_PROVIDER=aws-kms needs KEK_AWS_KMS_KEY_ID: /);
  });

  it('passes the warnings on to the boot log', async () => {
    const warnings: KekWarning[] = [];

    await boot({ KEK_PROVIDER: 'aws-kms', KEK_AWS_KMS_KEY_ID: ARN, KEK_PATH: '/k' }, warnings);

    expect(warnings.map((warning) => warning.variable)).toEqual(['KEK_PATH']);
  });

  it('exports the factory, the provider name and the encryption-context keys only', () => {
    expect(Object.keys(adapter).sort()).toEqual([
      'AWS_KMS_KEK_PROVIDER',
      'ENCRYPTION_CONTEXT_KEYS',
      'createKekProvider',
    ]);
  });
});
