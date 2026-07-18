import type { CredentialProvider } from '@qauth-labs/server-federation';
import type { FastifyPluginOptions } from 'fastify';

/**
 * Federation plugin configuration options
 */
export interface FederationPluginOptions extends FastifyPluginOptions {
  /**
   * Providers to seed the registry with at registration (e.g. the configured
   * set at auth-server bootstrap) - optional, defaults to none so providers
   * can also be registered imperatively via `fastify.providerRegistry.register()`
   */
  providers?: readonly CredentialProvider[];
}
