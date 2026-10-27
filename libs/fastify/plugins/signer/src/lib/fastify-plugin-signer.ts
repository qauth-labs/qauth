import type { Signer } from '@qauth-labs/server-keys';
import { createInProcessSigner, loadKekProvider } from '@qauth-labs/server-keys/custody';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { SignerPluginOptions } from '../types';
import { bootRealmKeysByName } from './realm-keys';
import { createRepositorySignerKeyStore } from './repository-key-stores';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The realm keys' signer (ADR-019 Decision 9). Every signature, every
     * `data_at_rest` encryption and every cookie HMAC secret goes through it.
     * Name the caller's role on each call, `'local'` in a single deployment.
     */
    signer: Signer;
  }
}

/**
 * The signer's wiring (issue #464): load the KEK provider, read keys through
 * the database repositories, and decorate the instance with the in-process
 * signer.
 *
 * This project is the only one, beside `@qauth-labs/server-keys` itself, that
 * may import `@qauth-labs/server-keys/custody`, the KEK provider and envelope
 * API (.oxlintrc.json). Everything else signs through `fastify.signer`.
 *
 * Registering it loads the KEK: outside production an unset KEK falls back to
 * the published development KEK with a warning, and `NODE_ENV=production`
 * refuses to start without one (`loadKekProvider`). Nothing is read from the
 * database until the first signature, unless `realmKeysBoot` is set: then the
 * key boot step (#485) runs in an `onReady` hook, so before the server
 * listens, and a refusal rejects `ready()`. Register the plugin after the
 * default realm's boot step, whose `onReady` hook creates the realm.
 *
 * @example
 * ```typescript
 * await fastify.register(signerPlugin, {
 *   db: fastify.db,
 *   kekEnv: process.env,
 *   enabledSignatureAlgorithms: cryptoEnv.enabledSignatureAlgorithms,
 *   hybridSigning: cryptoEnv.HYBRID_SIGNING_ENABLED,
 * });
 *
 * const token = await fastify.signer.signJws('local', {
 *   realmId,
 *   purpose: 'token_signing',
 *   typ: 'at+jwt',
 *   claims: { sub, aud, iat, exp },
 * });
 * ```
 */
export const signerPlugin = fp<SignerPluginOptions>(
  async (fastify: FastifyInstance, options: SignerPluginOptions) => {
    const kekProvider = await loadKekProvider({
      env: options.kekEnv,
      warn: ({ variable, message }) => fastify.log.warn({ variable }, message),
    });
    // A provider may keep a backend session alive, such as a Vault token it
    // renews: release it with the server.
    fastify.addHook('onClose', async () => {
      await kekProvider.close?.();
    });

    if (options.realmKeysBoot !== undefined) {
      const settings = options.realmKeysBoot;
      fastify.addHook('onReady', async () => {
        await bootRealmKeysByName(
          {
            db: options.db,
            kekProvider,
            enabledSignatureAlgorithms: options.enabledSignatureAlgorithms,
            hybridSigning: options.hybridSigning,
            log: fastify.log,
          },
          settings
        );
      });
    }

    fastify.decorate(
      'signer',
      createInProcessSigner({
        store: createRepositorySignerKeyStore(options.db),
        kekProvider,
        enabledSignatureAlgorithms: options.enabledSignatureAlgorithms,
        hybridSigning: options.hybridSigning,
        ...(options.keyCacheSize !== undefined ? { keyCacheSize: options.keyCacheSize } : {}),
        ...(options.refreshIntervalMs !== undefined
          ? { refreshIntervalMs: options.refreshIntervalMs }
          : {}),
      })
    );
  },
  { name: packageJson.name }
);
