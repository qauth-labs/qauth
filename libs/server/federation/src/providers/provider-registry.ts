import {
  ProviderAlreadyRegisteredError,
  ProviderNotRegisteredError,
} from '@qauth-labs/shared-errors';

import type { AuthMethod } from '../auth-method/auth-method.interface';
import { assertAuthMethod, declaresAuthMethodContract } from '../auth-method/validate';
import type { CredentialProvider } from './credential-provider.interface';

/**
 * Runtime registry mapping a credential `type` to its {@link CredentialProvider}
 * implementation. Populated once at auth-server bootstrap (via config/DI) and
 * queried by the auth engine, which resolves a provider by `type` and delegates
 * verification to it without any provider-specific branching (ADR-003).
 *
 * It holds AuthMethod entries (#599, EXPERIMENTAL) beside plain providers, in
 * the same `type` space: an AuthMethod is a `CredentialProvider`, so
 * {@link ProviderRegistry.resolve} finds it like any other, and a duplicate
 * `type` fails whichever kind came second.
 */
export interface ProviderRegistry {
  /**
   * Register a provider under its `provider.type`. A provider that carries a
   * `contract` member is an AuthMethod and must meet the whole contract.
   *
   * @throws {AuthMethodContractError} when an AuthMethod does not meet the
   * contract (a wrong contract version, a route outside its prefix, …)
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
  /**
   * Resolve the AuthMethod registered for `type`.
   *
   * @throws {ProviderNotRegisteredError} if no AuthMethod is registered for
   * `type`, a plain provider (`password`, `wallet`) included.
   * @experimental
   */
  resolveAuthMethod(type: string): AuthMethod;
  /** Whether a provider is registered for `type`. */
  has(type: string): boolean;
  /**
   * Every registered AuthMethod, in registration order: what the host mounts
   * routes for and the upstream step lists.
   *
   * @experimental
   */
  authMethods(): readonly AuthMethod[];
}

/**
 * Create a {@link ProviderRegistry}, optionally seeded with the providers
 * resolved from config/DI at auth-server bootstrap.
 *
 * Seeding reuses {@link ProviderRegistry.register}, so a misconfigured pair of
 * providers sharing a `type` fails fast at startup rather than silently letting
 * one shadow the other, and an AuthMethod that does not meet the contract
 * fails the boot.
 *
 * @param initialProviders providers to register up front (e.g. the configured
 * set at bootstrap). Defaults to none, supporting imperative registration.
 */
export function createProviderRegistry(
  initialProviders: readonly CredentialProvider[] = []
): ProviderRegistry {
  const providers = new Map<string, CredentialProvider>();
  const methods = new Map<string, AuthMethod>();

  const registry: ProviderRegistry = {
    register(provider: CredentialProvider): void {
      // The contract first, so a broken method reports its own problems
      // rather than a clash its broken `type` may cause.
      const method = declaresAuthMethodContract(provider) ? provider : undefined;
      if (method !== undefined) assertAuthMethod(method);
      if (providers.has(provider.type)) {
        throw new ProviderAlreadyRegisteredError(provider.type);
      }
      providers.set(provider.type, provider);
      if (method !== undefined) methods.set(method.type, method as AuthMethod);
    },
    resolve(type: string): CredentialProvider {
      const provider = providers.get(type);
      if (!provider) {
        throw new ProviderNotRegisteredError(type);
      }
      return provider;
    },
    resolveAuthMethod(type: string): AuthMethod {
      const method = methods.get(type);
      if (!method) {
        throw new ProviderNotRegisteredError(type);
      }
      return method;
    },
    has(type: string): boolean {
      return providers.has(type);
    },
    authMethods(): readonly AuthMethod[] {
      return Object.freeze([...methods.values()]);
    },
  };

  for (const provider of initialProviders) {
    registry.register(provider);
  }

  return registry;
}
