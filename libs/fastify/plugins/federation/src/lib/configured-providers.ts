import {
  createPasswordProvider,
  createWalletProvider,
  type CredentialProvider,
} from '@qauth-labs/server-federation';

/**
 * Feature-flag inputs that decide which {@link CredentialProvider}s the registry
 * is seeded with at bootstrap.
 *
 * Fields are REQUIRED on purpose: a bootstrap that gains a new upstream must
 * make a deliberate decision about it rather than inheriting a default from
 * this lib, and typecheck — not a code review — is what enforces that.
 */
export interface ConfiguredProvidersOptions {
  /**
   * `WALLET_FEDERATION_ENABLED` (#232). When `false` — the default posture of
   * the env schema — the wallet provider is not constructed and not registered,
   * so `providerRegistry.has('wallet')` is `false` and every existing auth flow
   * is bit-for-bit unchanged.
   */
  walletFederationEnabled: boolean;
}

/**
 * Resolve the configured provider set from feature flags (ADR-003, #232).
 *
 * This is the single place where "which upstreams exist" is decided, and it is
 * a PURE function of config: no I/O, no Fastify, no database. That is
 * deliberate — it makes the flag→registry contract unit-testable without
 * booting the auth-server (which would need Postgres and Redis), so the #232
 * acceptance criteria are provable in CI rather than argued in review.
 *
 * `PasswordProvider` is unconditional: it is the Phase 1 authentication method
 * every deployment depends on, never a flag-gated one.
 *
 * @param options - flag state, normally straight from the parsed env.
 * @returns the providers to seed the provider registry with, in registration
 * order. The registry rejects duplicate `type`s, so this list is a set by
 * construction.
 */
export function createConfiguredProviders(
  options: ConfiguredProvidersOptions
): readonly CredentialProvider[] {
  const providers: CredentialProvider[] = [createPasswordProvider()];

  // Strict `=== true`, not truthiness: this is a security gate, and the string
  // 'false' — what an unparsed `process.env.WALLET_FEDERATION_ENABLED` would
  // hand us — is truthy in JavaScript. The env schema returns a real boolean,
  // so this only ever fires for a caller that bypassed it; when one does, the
  // flag must read as OFF.
  //
  // WalletProvider (ADR-004) is a skeleton until #233–#238 land: registering it
  // is inert because its methods fail closed, and nothing resolves 'wallet'
  // yet. Enabling the flag today proves the wiring, it does not open a login
  // path.
  if (options.walletFederationEnabled === true) {
    providers.push(createWalletProvider());
  }

  return providers;
}
