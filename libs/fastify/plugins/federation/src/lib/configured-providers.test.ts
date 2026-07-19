import { PASSWORD_PROVIDER_TYPE, WALLET_PROVIDER_TYPE } from '@qauth-labs/server-federation';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterEach, describe, expect, it } from 'vitest';

import { createConfiguredProviders } from './configured-providers';
import { federationPlugin } from './federation-plugin';

/**
 * Acceptance criteria of issue #232, proved without Postgres or Redis: the
 * whole flag→registry decision is a pure function feeding the plugin, so the
 * only thing that has to boot is Fastify itself.
 *
 * - AC1: WalletProvider is registered and resolvable when the flag is on.
 * - AC2: NO behaviour change to any existing auth flow when the flag is off.
 */
describe('createConfiguredProviders (WALLET_FEDERATION_ENABLED wiring, #232)', () => {
  let app: FastifyInstance | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  /** Boot the real plugin over the real configured provider set. */
  async function bootWithFlag(walletFederationEnabled: boolean): Promise<FastifyInstance> {
    app = Fastify({ logger: false });
    await app.register(federationPlugin, {
      providers: createConfiguredProviders({ walletFederationEnabled }),
    });
    await app.ready();
    return app;
  }

  describe('AC1 — flag ON', () => {
    it("registers the wallet provider and resolves 'wallet' to it", async () => {
      const fastify = await bootWithFlag(true);

      expect(fastify.providerRegistry.has(WALLET_PROVIDER_TYPE)).toBe(true);
      const provider = fastify.providerRegistry.resolve(WALLET_PROVIDER_TYPE);
      expect(provider.type).toBe(WALLET_PROVIDER_TYPE);
    });

    it('resolves the fail-closed skeleton, not some other provider', async () => {
      // Identity check on behaviour: the thing registered under 'wallet' is the
      // #232 skeleton, so enabling the flag cannot authenticate anyone.
      const fastify = await bootWithFlag(true);
      const provider = fastify.providerRegistry.resolve(WALLET_PROVIDER_TYPE);

      await expect(provider.verify({ vp_token: 'x' })).rejects.toThrow(/#232/);
    });
  });

  describe('AC1 — flag OFF (the default)', () => {
    it("does not register 'wallet'", async () => {
      const fastify = await bootWithFlag(false);
      expect(fastify.providerRegistry.has(WALLET_PROVIDER_TYPE)).toBe(false);
    });

    it("fails to resolve 'wallet'", async () => {
      const fastify = await bootWithFlag(false);
      expect(() => fastify.providerRegistry.resolve(WALLET_PROVIDER_TYPE)).toThrow(
        /No credential provider is registered/
      );
    });

    it('treats a non-boolean truthy flag value as OFF (fail-safe)', () => {
      // An unparsed `process.env.WALLET_FEDERATION_ENABLED='false'` is truthy in
      // JS; the strict `=== true` check is what stops that from enabling wallet
      // federation. Cast because the type system already forbids this call.
      const providers = createConfiguredProviders({
        walletFederationEnabled: 'false' as unknown as boolean,
      });

      expect(providers.map((p) => p.type)).toEqual([PASSWORD_PROVIDER_TYPE]);
    });
  });

  describe('AC2 — the password flow is unchanged in BOTH flag states', () => {
    it.each([
      ['off', false],
      ['on', true],
    ])(
      'resolves an identical, working password provider with the flag %s',
      async (_label, flag) => {
        const fastify = await bootWithFlag(flag);

        expect(fastify.providerRegistry.has(PASSWORD_PROVIDER_TYPE)).toBe(true);
        const provider = fastify.providerRegistry.resolve(PASSWORD_PROVIDER_TYPE);
        const identity = await provider.verify({
          email: 'user@example.com',
          passwordHash: '$argon2id$fake',
          emailVerified: true,
        });

        expect(identity).toEqual({
          externalSub: 'user@example.com',
          assuranceLevel: 'low',
          rawClaims: { email: 'user@example.com', email_verified: true },
        });
        expect(provider.extractAttributes(identity)).toEqual([
          {
            source: 'self_reported',
            attrKey: 'email',
            attrValue: 'user@example.com',
            verified: true,
          },
        ]);
      }
    );

    it('seeds ONLY the password provider when the flag is off', () => {
      // Pins the whole set, so a future provider cannot arrive unflagged.
      expect(
        createConfiguredProviders({ walletFederationEnabled: false }).map((p) => p.type)
      ).toEqual([PASSWORD_PROVIDER_TYPE]);
    });

    it('adds the wallet provider without disturbing the order when the flag is on', () => {
      expect(
        createConfiguredProviders({ walletFederationEnabled: true }).map((p) => p.type)
      ).toEqual([PASSWORD_PROVIDER_TYPE, WALLET_PROVIDER_TYPE]);
    });
  });
});
