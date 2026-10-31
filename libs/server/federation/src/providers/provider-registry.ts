import {
  ProviderAlreadyRegisteredError,
  ProviderNotRegisteredError,
} from '@qauth-labs/shared-errors';

import type { AuthMethod } from '../auth-method/auth-method.interface';
import {
  assertAuthMethod,
  authMethodSnapshot,
  declaresAuthMethodContract,
} from '../auth-method/validate';
import type {
  CredentialProvider,
  UserAttribute,
  VerifiedIdentity,
} from './credential-provider.interface';

/**
 * Runtime registry mapping a credential `type` to its {@link CredentialProvider}
 * implementation. Populated once at auth-server bootstrap (via config/DI) and
 * queried by the auth engine, which resolves a provider by `type` and delegates
 * verification to it without any provider-specific branching (ADR-003).
 *
 * It holds AuthMethod entries (#599, EXPERIMENTAL) beside plain providers, in
 * the same `type` space, so a duplicate `type` fails whichever kind came
 * second. An AuthMethod's `verify()` is not fail-closed the way
 * `WalletProvider`'s is: it resolves for its own callback's results. So only
 * {@link ProviderRegistry.resolveAuthMethod} hands one out, for the engine's
 * upstream step; {@link ProviderRegistry.resolve} answers a stand-in whose
 * `verify()` and `extractAttributes()` refuse.
 */
export interface ProviderRegistry {
  /**
   * Register a provider under its `provider.type`. A provider that carries a
   * `contract` member is an AuthMethod and must meet the whole contract; the
   * registry keeps a frozen snapshot of it, which `resolveAuthMethod`
   * answers (`resolve` answers a fail-closed stand-in).
   *
   * @throws {AuthMethodContractError} when an AuthMethod does not meet the
   * contract (a wrong contract version, a route outside its prefix, …)
   * @throws {ProviderAlreadyRegisteredError} if a provider is already registered
   * for that type (fail-fast against provider-confusion shadowing).
   */
  register(provider: CredentialProvider): void;
  /**
   * Resolve the provider registered for `type`. For an AuthMethod's type it
   * answers a fail-closed stand-in, the same one at every call: its `type`,
   * a `verify()` that rejects and an `extractAttributes()` that throws. An
   * AuthMethod verifies only through the upstream step
   * (`resolveAuthMethod`, then `completeUpstreamStep`), never through a
   * generic credential path. Plain providers are answered as registered.
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
  /**
   * The AuthMethod registered for `type`, or `undefined`: for a type that
   * comes from a request, such as the provider a person picked, where an
   * unknown type is the request's fault and not a server invariant.
   *
   * @experimental
   */
  findAuthMethod(type: string): AuthMethod | undefined;
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
      // An AuthMethod is kept as a frozen snapshot, validated as it is kept:
      // the type checked is the type stored, and nothing it holds changes
      // later. The contract first, so a broken method reports its own
      // problems rather than a clash its broken `type` may cause.
      let method: AuthMethod | undefined;
      if (declaresAuthMethodContract(provider)) {
        const snapshot = authMethodSnapshot(provider);
        assertAuthMethod(snapshot);
        method = snapshot;
      }
      const type = (method ?? provider).type;
      if (providers.has(type)) {
        throw new ProviderAlreadyRegisteredError(type);
      }
      providers.set(type, method === undefined ? provider : failClosedStandIn(type));
      if (method !== undefined) methods.set(type, method);
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
    findAuthMethod(type: string): AuthMethod | undefined {
      return methods.get(type);
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

/**
 * What `resolve()` answers for an AuthMethod's type: the type, and members
 * that refuse. An AuthMethod's own `verify()` resolves for its callback's
 * results; handing it to a generic credential path would let that path sign
 * someone in without the upstream step's checks.
 */
function failClosedStandIn(type: string): CredentialProvider {
  const refusal = () =>
    new Error(
      `The AuthMethod ${type} verifies only through the upstream step: resolve it with resolveAuthMethod() and hand its callback's outcome to completeUpstreamStep()`
    );
  return Object.freeze({
    type,
    async verify(): Promise<VerifiedIdentity> {
      throw refusal();
    },
    extractAttributes(): UserAttribute[] {
      throw refusal();
    },
  });
}
