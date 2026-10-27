import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

import { signerPlugin, type SignerPluginOptions } from '@qauth-labs/fastify-plugin-signer';
import Fastify from 'fastify';
import { describe, expect, it } from 'vitest';

/**
 * KEK adapters are optional packages (ADR-019 Decision 9, #577, #578). The auth
 * server depends on none of them, and its boot loads one only when
 * `KEK_PROVIDER` names it.
 *
 * The KEK provider is loaded when `app.ts` registers the signer's wiring with
 * `process.env`. Here the wiring is registered the same way, from the auth
 * server's own installation, so the package lookup is the one the server
 * makes. The signer reads no database until its first signature.
 */

const APP_ROOT = resolve(__dirname, '../..');
const WORKSPACE_ROOT = resolve(APP_ROOT, '../..');
const NO_DB = {} as SignerPluginOptions['db'];
const KEK = Buffer.alloc(32, 0x5c).toString('base64');
const KEY_ARN = 'arn:aws:kms:eu-central-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab';

/** Each adapter package with settings it accepts, so the boot reaches the package lookup. */
const ADAPTERS: ReadonlyArray<readonly [string, string, Record<string, string>]> = [
  ['aws-kms', '@qauth-labs/keys-aws-kms', { KEK_AWS_KMS_KEY_ID: KEY_ARN }],
  [
    'vault',
    '@qauth-labs/keys-vault',
    {
      KEK_VAULT_ADDR: 'https://vault.invalid:8200',
      KEK_VAULT_TRANSIT_KEY: 'qauth-kek',
      KEK_VAULT_TOKEN_FILE: '/nonexistent/vault-token',
    },
  ],
];

function dependencies(packageJsonPath: string): string[] {
  const manifest = JSON.parse(readFileSync(join(WORKSPACE_ROOT, packageJsonPath), 'utf8')) as {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  };
  return [
    ...Object.keys(manifest.dependencies ?? {}),
    ...Object.keys(manifest.devDependencies ?? {}),
  ];
}

/** Register the signer's wiring as `app.ts` does and wait for the boot. */
async function boot(kekEnv: Record<string, string>) {
  const app = Fastify({ logger: false });
  try {
    await app.register(signerPlugin, {
      db: NO_DB,
      kekEnv,
      enabledSignatureAlgorithms: ['EdDSA'],
      hybridSigning: false,
    });
    await app.ready();
    return app;
  } catch (error) {
    await app.close();
    throw error;
  }
}

describe('the auth server and the KEK adapter packages', () => {
  it.each([
    'apps/auth-server/package.json',
    'libs/fastify/plugins/signer/package.json',
    'libs/server/keys/package.json',
  ])('%s depends on no KEK adapter package', (path) => {
    expect(dependencies(path).filter((name) => name.startsWith('@qauth-labs/keys-'))).toEqual([]);
  });

  it.each([
    ['unset', { KEK, NODE_ENV: 'test' }],
    ['local', { KEK_PROVIDER: 'local', KEK, NODE_ENV: 'test' }],
    ['local in production', { KEK_PROVIDER: 'local', KEK, NODE_ENV: 'production' }],
  ])('starts without the adapter when KEK_PROVIDER is %s', async (_what, kekEnv) => {
    const app = await boot(kekEnv);

    expect(typeof app.signer.signJws).toBe('function');
    await app.close();
  });

  // The lookup `loadKekProvider` itself makes: the package is not installed
  // where the auth server would find it.
  it.each(ADAPTERS)(
    'loads the adapter only when KEK_PROVIDER=%s, naming the package to install',
    async (name, adapter, settings) => {
      const error = await boot({ KEK_PROVIDER: name, ...settings, NODE_ENV: 'production' }).then(
        () => undefined,
        (reason: unknown) => reason
      );

      expect(error).toMatchObject({
        name: 'InvalidConfigurationError',
        details: { variable: 'KEK_PROVIDER', value: name, package: adapter },
      });
      expect((error as Error).message).toContain('whose package is not installed');
    }
  );
});
