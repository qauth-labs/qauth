import { createProviderRegistry, type ProviderRegistry } from '@qauth-labs/server-federation';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';
import type { FederationPluginOptions } from '../types';

declare module 'fastify' {
  interface FastifyInstance {
    providerRegistry: ProviderRegistry;
  }
}

/**
 * Fastify plugin for the federation provider registry.
 * Decorates fastify instance with providerRegistry, mapping a credential
 * `type` to its CredentialProvider implementation (ADR-003). The auth engine
 * resolves providers by type and delegates verification without any
 * provider-specific branching.
 *
 * Seeding reuses the registry's own `register()`, so two configured providers
 * sharing a `type` fail fast at startup instead of silently shadowing each other.
 *
 * @example
 * ```typescript
 * await fastify.register(federationPlugin, {
 *   providers: [createPasswordProvider()],
 * });
 *
 * // Use in routes
 * const provider = fastify.providerRegistry.resolve('password');
 * const identity = await provider.verify(input);
 * ```
 */
export const federationPlugin = fp<FederationPluginOptions>(
  async (fastify: FastifyInstance, options: FederationPluginOptions) => {
    const providerRegistry = createProviderRegistry(options.providers);

    fastify.decorate('providerRegistry', providerRegistry);

    fastify.log.debug('Federation plugin registered');
  },
  {
    name: packageJson.name,
  }
);
