import {
  ProviderAlreadyRegisteredError,
  ProviderNotRegisteredError,
} from '@qauth-labs/shared-errors';

import type { CredentialProvider } from './credential-provider.interface';

/**
 * Runtime registry mapping a credential `type` to its {@link CredentialProvider}
 * implementation. Populated once at auth-server bootstrap (via config/DI) and
 * queried by the auth engine, which resolves a provider by `type` and delegates
 * verification to it without any provider-specific branching (ADR-003).
 */
export interface ProviderRegistry {
  /**
   * Register a provider under its `provider.type`.
   *
   * @throws {ProviderAlreadyRegisteredError} if a provider is already registered
   * for that type (fail-fast against provider-confusion shadowing).
   */
  register(provider: CredentialProvider): void;
  /**
   * Resolve the provider registered for `type`.
   *
   * @throws {ProviderNotRegisteredError} if no provider is registered for `type`.
   */
  resolve(type: string): CredentialProvider;
  /** Whether a provider is registered for `type`. */
  has(type: string): boolean;
}

/**
 * Create a {@link ProviderRegistry}, optionally seeded with the providers
 * resolved from config/DI at auth-server bootstrap.
 *
 * Seeding reuses {@link ProviderRegistry.register}, so a misconfigured pair of
 * providers sharing a `type` fails fast at startup rather than silently letting
 * one shadow the other.
 *
 * @param initialProviders providers to register up front (e.g. the configured
 * set at bootstrap). Defaults to none, supporting imperative registration.
 */
export function createProviderRegistry(
  initialProviders: readonly CredentialProvider[] = []
): ProviderRegistry {
  const providers = new Map<string, CredentialProvider>();

  const registry: ProviderRegistry = {
    register(provider: CredentialProvider): void {
      if (providers.has(provider.type)) {
        throw new ProviderAlreadyRegisteredError(provider.type);
      }
      providers.set(provider.type, provider);
    },
    resolve(type: string): CredentialProvider {
      const provider = providers.get(type);
      if (!provider) {
        throw new ProviderNotRegisteredError(type);
      }
      return provider;
    },
    has(type: string): boolean {
      return providers.has(type);
    },
  };

  for (const provider of initialProviders) {
    registry.register(provider);
  }

  return registry;
}
