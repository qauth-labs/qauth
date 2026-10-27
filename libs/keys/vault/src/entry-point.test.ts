import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import {
  kekProviderPackage,
  type KekWarning,
  loadKekProvider,
} from '@qauth-labs/server-keys/custody';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { afterAll, describe, expect, it } from 'vitest';

import * as adapter from './index';
import { createSecretFiles } from './testing/double-provider';

const packageJson = JSON.parse(readFileSync(join(__dirname, '../package.json'), 'utf8')) as {
  name: string;
};

const files = createSecretFiles();
afterAll(() => files.cleanup());

const SETTINGS = {
  KEK_PROVIDER: 'vault',
  // Never dialled: creating the provider makes no Vault call.
  KEK_VAULT_ADDR: 'https://vault.invalid:8200',
  KEK_VAULT_TRANSIT_KEY: 'qauth-kek',
  KEK_VAULT_TOKEN_FILE: files.write('hvs.entry-point-test-token'),
};

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

describe('the package as KEK_PROVIDER=vault loads it', () => {
  it('is the package the key library imports for vault', () => {
    expect(kekProviderPackage(adapter.VAULT_KEK_PROVIDER)).toBe(packageJson.name);
    expect(packageJson.name).toBe('@qauth-labs/keys-vault');
  });

  it('gives the loader a provider under its own name, without calling Vault', async () => {
    const provider = await boot(SETTINGS);

    expect(provider.name).toBe('vault');
  });

  it('stops the boot with a clear message when KEK_VAULT_ADDR is missing', async () => {
    const error = await boot({ ...SETTINGS, KEK_VAULT_ADDR: '' }).then(
      () => undefined,
      (reason: unknown) => reason
    );

    expect(error).toBeInstanceOf(InvalidConfigurationError);
    expect((error as Error).message).toMatch(/^KEK_PROVIDER=vault needs KEK_VAULT_ADDR: /);
  });

  it('passes the warnings on to the boot log', async () => {
    const warnings: KekWarning[] = [];

    await boot({ ...SETTINGS, KEK_PATH: '/k' }, warnings);

    expect(warnings.map((warning) => warning.variable)).toEqual(['KEK_PATH']);
  });

  it('exports the factory and the provider name only', () => {
    expect(Object.keys(adapter).sort()).toEqual(['VAULT_KEK_PROVIDER', 'createKekProvider']);
  });
});
