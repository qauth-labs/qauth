import {
  createPasswordProvider,
  type CredentialProvider,
  PASSWORD_PROVIDER_TYPE,
} from '@qauth-labs/server-federation';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { federationPlugin } from './federation-plugin';

describe('federationPlugin', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  async function bootApp(providers?: readonly CredentialProvider[]): Promise<FastifyInstance> {
    app = Fastify({ logger: false });
    await app.register(federationPlugin, providers ? { providers } : {});
    await app.ready();
    return app;
  }

  it('decorates providerRegistry and resolves the seeded password provider', async () => {
    const fastify = await bootApp([createPasswordProvider()]);

    expect(fastify.providerRegistry.has(PASSWORD_PROVIDER_TYPE)).toBe(true);
    const provider = fastify.providerRegistry.resolve(PASSWORD_PROVIDER_TYPE);
    const identity = await provider.verify({
      email: 'user@example.com',
      passwordHash: '$argon2id$fake',
      emailVerified: false,
    });
    expect(identity.externalSub).toBe('user@example.com');
  });

  it('boots with an empty registry when no providers are configured', async () => {
    const fastify = await bootApp();
    expect(fastify.providerRegistry.has(PASSWORD_PROVIDER_TYPE)).toBe(false);
  });

  it('fails fast at startup when two configured providers share a type', async () => {
    app = Fastify({ logger: false });
    await expect(
      app
        .register(federationPlugin, {
          providers: [createPasswordProvider(), createPasswordProvider()],
        })
        .ready()
    ).rejects.toThrow(/already registered/);
  });

  /**
   * Epic #224 acceptance criterion (ADR-003's promise): a NEW
   * CredentialProvider can be registered with ZERO changes to auth-engine
   * code. The proof is this file's import graph — it imports nothing from
   * apps/auth-server (no routes, no helpers, no app internals) and modifies no
   * source file; the stub goes in through the same public registry API the
   * bootstrap uses, and every interface method functions.
   */
  it('a new CredentialProvider registers with zero auth-engine changes (ADR-003 epic AC)', async () => {
    const fastify = await bootApp([createPasswordProvider()]);

    const stubProvider: CredentialProvider = {
      type: 'test-stub',
      verify: async () => ({
        externalSub: 'stub-subject',
        assuranceLevel: 'high',
        rawClaims: { name: 'Stub User' },
      }),
      extractAttributes: (identity) => [
        {
          source: 'test-stub',
          attrKey: 'name',
          attrValue: String(identity.rawClaims['name']),
          verified: true,
        },
      ],
    };

    fastify.providerRegistry.register(stubProvider);

    expect(fastify.providerRegistry.has('test-stub')).toBe(true);
    const resolved = fastify.providerRegistry.resolve('test-stub');
    const identity = await resolved.verify({ anything: 'goes' });
    expect(identity).toEqual({
      externalSub: 'stub-subject',
      assuranceLevel: 'high',
      rawClaims: { name: 'Stub User' },
    });
    expect(resolved.extractAttributes(identity)).toEqual([
      { source: 'test-stub', attrKey: 'name', attrValue: 'Stub User', verified: true },
    ]);
    // The password provider is untouched by the addition.
    expect(fastify.providerRegistry.has(PASSWORD_PROVIDER_TYPE)).toBe(true);
  });
});
