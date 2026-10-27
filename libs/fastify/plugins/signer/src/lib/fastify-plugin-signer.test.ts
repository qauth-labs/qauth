import type { DbClient } from '@qauth-labs/infra-db';
import { SIGNER_OPERATIONS } from '@qauth-labs/server-keys';
import Fastify from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import type { SignerPluginOptions } from '../types';
import { signerPlugin } from './fastify-plugin-signer';

/** The loaded KEK provider, given a `close` the tests can watch. */
const providerClose = vi.hoisted(() => vi.fn());
vi.mock('@qauth-labs/server-keys/custody', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@qauth-labs/server-keys/custody')>();
  return {
    ...actual,
    loadKekProvider: async (...args: Parameters<typeof actual.loadKekProvider>) => ({
      ...(await actual.loadKekProvider(...args)),
      close: providerClose,
    }),
  };
});

/** Registration never reads the database, so a stand-in is enough here. */
const NO_DB = {} as DbClient;
const KEK = Buffer.alloc(32, 0xa1).toString('base64');

function options(overrides: Partial<SignerPluginOptions> = {}): SignerPluginOptions {
  return {
    db: NO_DB,
    kekEnv: { KEK, NODE_ENV: 'test' },
    enabledSignatureAlgorithms: ['EdDSA'],
    hybridSigning: false,
    ...overrides,
  };
}

describe('signerPlugin', () => {
  it('decorates the instance with the signer and its operations only', async () => {
    const app = Fastify({ logger: false });
    await app.register(signerPlugin, options());
    await app.ready();

    expect(Object.keys(app.signer).sort()).toEqual([...SIGNER_OPERATIONS].sort());
    await app.close();
  });

  it('closes the KEK provider when the server closes, and not before', async () => {
    providerClose.mockClear();
    const app = Fastify({ logger: false });
    await app.register(signerPlugin, options());
    await app.ready();

    expect(providerClose).not.toHaveBeenCalled();
    await app.close();
    expect(providerClose).toHaveBeenCalledTimes(1);
  });

  it('refuses to start in production without a KEK', async () => {
    const app = Fastify({ logger: false });
    app.register(signerPlugin, options({ kekEnv: { NODE_ENV: 'production' } }));

    await expect(app.ready()).rejects.toMatchObject({ name: 'InvalidConfigurationError' });
    await app.close();
  });

  it('logs the development KEK warning without the KEK', async () => {
    const app = Fastify({ logger: false });
    const warn = vi.spyOn(app.log, 'warn');
    await app.register(signerPlugin, options({ kekEnv: { NODE_ENV: 'development' } }));
    await app.ready();

    expect(warn).toHaveBeenCalledWith({ variable: 'KEK' }, expect.any(String));
    await app.close();
  });

  it('refuses hybrid signing that SIGNING_ALGORITHM_MODE does not enable', async () => {
    const app = Fastify({ logger: false });
    app.register(signerPlugin, options({ hybridSigning: true }));

    await expect(app.ready()).rejects.toMatchObject({ name: 'InvalidConfigurationError' });
    await app.close();
  });
});
