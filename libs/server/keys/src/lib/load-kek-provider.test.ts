import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

import { KEK_A, localProvider } from '../testing/keks';
import type { KekProvider, KekProviderContext, KekWarning } from './kek-provider';
import {
  DEFAULT_KEK_PROVIDER,
  type ImportKekProviderModule,
  KEK_PROVIDER_NAME,
  kekProviderPackage,
  loadKekProvider,
} from './load-kek-provider';

function context(env: Record<string, string>, warnings: KekWarning[] = []): KekProviderContext {
  return { env: { NODE_ENV: 'test', ...env }, warn: (warning) => warnings.push(warning) };
}

const noImport: ImportKekProviderModule = async (specifier) => {
  throw new Error(`no adapter should be imported, got ${specifier}`);
};

/** An adapter double: a provider that forwards to a default provider under another name. */
function adapterProvider(name: string): KekProvider {
  return { ...localProvider({ KEK: KEK_A }), name };
}

async function refusal(promise: Promise<unknown>): Promise<InvalidConfigurationError> {
  const error = await promise.then(
    () => undefined,
    (reason: unknown) => reason
  );
  expect(error).toBeInstanceOf(InvalidConfigurationError);
  return error as InvalidConfigurationError;
}

describe('loadKekProvider', () => {
  it('selects the default provider when KEK_PROVIDER is unset or blank', async () => {
    expect(DEFAULT_KEK_PROVIDER).toBe('local');
    expect((await loadKekProvider(context({ KEK: KEK_A }), noImport)).name).toBe('local');
    expect(
      (await loadKekProvider(context({ KEK: KEK_A, KEK_PROVIDER: '  ' }), noImport)).name
    ).toBe('local');
  });

  it('selects the default provider by name, and imports no package for it', async () => {
    const provider = await loadKekProvider(
      context({ KEK: KEK_A, KEK_PROVIDER: 'local' }),
      noImport
    );

    expect(provider.name).toBe('local');
  });

  it('passes the default provider its warnings', async () => {
    const warnings: KekWarning[] = [];

    await loadKekProvider(context({}, warnings), noImport);

    expect(warnings.map((warning) => warning.variable)).toEqual(['KEK']);
  });

  it('loads an adapter by name from @qauth-labs/keys-<name> and hands it the context', async () => {
    const createKekProvider = vi.fn(() => adapterProvider('cloud-kms'));
    const importAdapter = vi.fn(async () => ({ createKekProvider }));
    const ctx = context({ KEK_PROVIDER: 'cloud-kms', KEK_CLOUD_KMS_KEY_ID: 'alias/qauth' });

    const provider = await loadKekProvider(ctx, importAdapter);

    expect(importAdapter).toHaveBeenCalledWith('@qauth-labs/keys-cloud-kms');
    expect(createKekProvider).toHaveBeenCalledWith(ctx);
    expect(provider.name).toBe('cloud-kms');
  });

  it('accepts an adapter whose factory is async or arrives as a CommonJS default export', async () => {
    const asyncFactory = await loadKekProvider(context({ KEK_PROVIDER: 'vault' }), async () => ({
      createKekProvider: async () => adapterProvider('vault'),
    }));
    const commonJs = await loadKekProvider(context({ KEK_PROVIDER: 'pkcs11' }), async () => ({
      default: { createKekProvider: () => adapterProvider('pkcs11') },
    }));

    expect(asyncFactory.name).toBe('vault');
    expect(commonJs.name).toBe('pkcs11');
  });

  it.each(['CLOUD-KMS', 'cloud_kms', '-kms', 'kms-', '../evil', '@scope/pkg', 'a--b'])(
    'refuses the malformed name %j before importing anything',
    async (name) => {
      const error = await refusal(loadKekProvider(context({ KEK_PROVIDER: name }), noImport));

      expect(error.details).toEqual({ variable: 'KEK_PROVIDER', value: name });
    }
  );

  it('refuses an adapter whose package is not installed, naming the package', async () => {
    // A real dynamic import, so the error is the one the runtime raises.
    const error = await refusal(
      loadKekProvider(context({ KEK_PROVIDER: 'not-installed-for-this-test' }))
    );

    expect(error.message).toContain('whose package is not installed');
    expect(error.details).toEqual({
      variable: 'KEK_PROVIDER',
      value: 'not-installed-for-this-test',
      package: '@qauth-labs/keys-not-installed-for-this-test',
    });
  });

  it("passes through a missing package the adapter itself imports, which is the adapter's fault", async () => {
    const inner = Object.assign(
      new Error(
        "Cannot find module 'cloud-kms-sdk'\nRequire stack:\n- /app/node_modules/@qauth-labs/keys-cloud-kms/src/index.ts"
      ),
      { code: 'MODULE_NOT_FOUND' }
    );

    await expect(
      loadKekProvider(context({ KEK_PROVIDER: 'cloud-kms' }), async () => {
        throw inner;
      })
    ).rejects.toBe(inner);
  });

  it('refuses a package that does not export createKekProvider', async () => {
    const error = await refusal(
      loadKekProvider(context({ KEK_PROVIDER: 'vault' }), async () => ({ createProvider: () => 1 }))
    );

    expect(error.message).toContain('does not export createKekProvider');
  });

  it('refuses an adapter that returns something that is not a provider', async () => {
    const error = await refusal(
      loadKekProvider(context({ KEK_PROVIDER: 'vault' }), async () => ({
        createKekProvider: () => ({ name: 'vault', wrap: () => undefined }),
      }))
    );

    expect(error.message).toContain('is not a KEK provider');
  });

  it("lets the adapter's own configuration error stop the boot", async () => {
    const missing = new InvalidConfigurationError('KEK_CLOUD_KMS_KEY_ID must be set.');

    await expect(
      loadKekProvider(context({ KEK_PROVIDER: 'cloud-kms' }), async () => ({
        createKekProvider: () => {
          throw missing;
        },
      }))
    ).rejects.toBe(missing);
  });
});

describe('kekProviderPackage and KEK_PROVIDER_NAME', () => {
  it('name each adapter package after its KEK_PROVIDER value', () => {
    expect(['cloud-kms', 'vault', 'pkcs11'].map(kekProviderPackage)).toEqual([
      '@qauth-labs/keys-cloud-kms',
      '@qauth-labs/keys-vault',
      '@qauth-labs/keys-pkcs11',
    ]);
    expect(['local', 'cloud-kms', 'vault', 'pkcs11'].every((n) => KEK_PROVIDER_NAME.test(n))).toBe(
      true
    );
  });
});
