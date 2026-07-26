import {
  createPasswordProvider,
  createWalletProvider,
  type CredentialProvider,
  NO_VERIFIER_MATERIAL,
  type ProvisionedVerifierMaterial,
  resolveVerifierProfile,
  VERIFIER_PROFILE_IDS,
  type VerifierProfile,
  type VerifierProfileId,
} from '@qauth-labs/server-federation';

/**
 * The shipped profile ids, re-exported for the one consumer that cannot reach
 * them any other way (#299).
 *
 * `apps/auth-server` (`scope:app`) may depend on `scope:fastify` and on
 * `server-config`, never on `scope:server` libs at large — so it can see
 * `server-config`'s `OID4VP_VERIFIER_PROFILE` enum and, through this export,
 * the profile table's ids. It is the ONLY place in the workspace that can see
 * both, which is what makes its env test the home of the cross-lib pin between
 * them: `server-config` deliberately carries no dependency on
 * `server-federation` (config is the lowest layer), so the enum duplicates
 * `VerifierProfileId` and nothing else in the workspace can compare the two
 * lists. Without this export the pin has nowhere to live.
 */
export { VERIFIER_PROFILE_IDS } from '@qauth-labs/server-federation';

/**
 * What the deployment's crypto layer can ACTUALLY produce — as opposed to what a
 * `VerifierProfile` declares it needs (#299).
 *
 * Handed in by the bootstrap rather than read from `@qauth-labs/core-crypto`
 * here, for two reasons. This lib has no business knowing how signing is
 * implemented, only what the answer is; and the answer is deployment-shaped —
 * #298 lands ES256 and the JWE stack, and an operator's `SIGNING_ALGORITHM_MODE`
 * allowlist can narrow it further. A declarative descriptor also keeps
 * {@link createConfiguredProviders} a pure function of config, which is the
 * property this whole module is built around.
 *
 * `signingAlgs` is `readonly string[]` rather than either union in play, on
 * purpose: `VerifierSigningAlgorithm` (`'EdDSA' | 'ES256'`) is what a profile
 * may DECLARE and `JwsAlgorithm` (`'EdDSA' | 'RS256'`) is what the token layer
 * can EMIT. They are different vocabularies until #298 reconciles them, and a
 * descriptor forced to pick one would have to silently drop `'RS256'` or
 * `'ES256'`. JOSE `alg` identifiers are the vocabulary they share; the
 * comparison is by value.
 */
export interface VerifierCryptoCapabilities {
  /** JOSE `alg` identifiers this deployment can sign a request with today. */
  readonly signingAlgs: readonly string[];
  /**
   * Whether this deployment can encrypt an Authorization Response — the JWE
   * behind the `direct_post.jwt` response mode HAIP §5.1 mandates. #298.
   */
  readonly responseEncryption: boolean;
}

/**
 * Feature-flag inputs that decide which {@link CredentialProvider}s the registry
 * is seeded with at bootstrap.
 *
 * Fields are REQUIRED on purpose: a bootstrap that gains a new upstream must
 * make a deliberate decision about it rather than inheriting a default from
 * this lib, and typecheck — not a code review — is what enforces that. The one
 * optional field ({@link provisionedVerifierMaterial}) is optional because it is
 * the only one whose omission is itself the fail-closed answer; see its doc.
 */
export interface ConfiguredProvidersOptions {
  /**
   * `WALLET_FEDERATION_ENABLED` (#232). When `false` — the default posture of
   * the env schema — the wallet provider is not constructed and not registered,
   * so `providerRegistry.has('wallet')` is `false` and every existing auth flow
   * is bit-for-bit unchanged.
   */
  walletFederationEnabled: boolean;

  /**
   * `OID4VP_VERIFIER_PROFILE` (#299) — which `VerifierProfile` the deployment
   * operates under, or `undefined` when the operator selected none.
   *
   * Required-but-nullable rather than optional, for the same reason the field
   * above is required: a bootstrap must state its profile decision explicitly,
   * and typecheck — not a code review — is what enforces that. `undefined` is a
   * decision ("none selected"), and when wallet federation is ON it is the
   * decision that refuses the boot.
   *
   * Read ONLY when {@link walletFederationEnabled} is `true`: a deployment that
   * never turns wallet federation on is unaffected by profile configuration.
   */
  verifierProfileId: VerifierProfileId | undefined;

  /**
   * What the deployment's crypto layer can produce (#299).
   *
   * REQUIRED and undefaulted, because there is no honest default. A permissive
   * one would let a profile boot on a crypto layer that cannot honour it, and a
   * fail-closed empty one would refuse `oid4vp-1.0-base` — the profile that runs
   * on today's crypto — and then advertise, in the refusal, that no profile is
   * selectable at all. The bootstrap is the only layer that knows the answer, so
   * it must supply it.
   */
  cryptoCapabilities: VerifierCryptoCapabilities;

  /**
   * X.509 material the operator has provisioned for the verifier identity (#299).
   *
   * The single exception to the required-fields rule above, and only because
   * omitting it is the fail-closed answer rather than an unstated one: nothing
   * is provisionable until #298/#233 ship a certificate configuration surface,
   * so the default is `NO_VERIFIER_MATERIAL` — the value that makes `haip-1.0`
   * refuse. This mirrors `assertPrefixProvisioned`'s own defaulted parameter: a
   * caller that forgets to thread it through fails closed rather than sails past.
   * When #298/#233 land, the bootstrap starts passing real material here and
   * `haip-1.0` clears the certificate half of the gate without an edit to this
   * signature.
   */
  provisionedVerifierMaterial?: ProvisionedVerifierMaterial;
}

/** Render identifiers as a quoted list, or `none` for the empty set. */
function quoteList(values: readonly string[]): string {
  return values.length === 0 ? 'none' : values.map((value) => `'${value}'`).join(', ');
}

/**
 * Refuse a profile whose declared crypto mandates this deployment cannot meet
 * (#299).
 *
 * `verifier-profile.types.ts` claims that declaring `ES256` on `haip-1.0` "is
 * precisely how that gap becomes visible and fail-closed". This is the code that
 * makes the claim true; until it existed nothing read `signingAlgs` or
 * `responseEncryption` at startup and the ONLY thing keeping `haip-1.0` out was
 * its missing certificate chain. So the moment #298/#233 provisioned a chain, a
 * `haip-1.0` deployment would have booted happily on an EdDSA-only crypto layer
 * and every EUDI wallet would have rejected every request — a boot-time
 * misconfiguration surfacing as a 100% production presentation failure, which is
 * the worst possible place to discover it.
 *
 * The two fields are read as REQUIREMENTS, and they are not the same shape:
 *   - `signingAlgs` is the set the profile ACCEPTS, so at least one member must
 *     be producible. `oid4vp-1.0-base` lists `EdDSA` and `ES256` and runs on
 *     `EdDSA` alone; `haip-1.0` lists only `ES256` (HAIP §7, where EdDSA is
 *     absent from the mandatory set) and so cannot run at all today.
 *   - `responseEncryption: 'required'` is a `CapabilityPosture`, and `required`
 *     means the JWE stack must exist outright.
 *
 * No profile is named here: adding `haip-1.1` must require editing the profile
 * table and nothing else (a #299 acceptance criterion), so this reads declared
 * capabilities and lets the data decide which deployments it excludes.
 *
 * @throws Error when the profile's mandates exceed {@link capabilities}.
 */
function assertProfileWithinCryptoCapabilities(
  profile: VerifierProfile,
  capabilities: VerifierCryptoCapabilities
): void {
  const usable = profile.signingAlgs.filter((alg) => capabilities.signingAlgs.includes(alg));

  if (usable.length === 0) {
    throw new Error(
      `Verifier profile '${profile.id}' accepts ${quoteList(profile.signingAlgs)} for request signing, but this deployment's crypto layer produces ${quoteList(capabilities.signingAlgs)}. Refusing to start rather than advertising the profile to wallets and then failing every presentation with a signature they will not accept (#299). ES256 lands with #298.`
    );
  }

  if (profile.responseEncryption === 'required' && !capabilities.responseEncryption) {
    throw new Error(
      `Verifier profile '${profile.id}' requires encrypted Authorization Responses — the 'direct_post.jwt' response mode of HAIP §5.1 — and this deployment has no JWE stack. Refusing to start rather than asking a wallet for a response it cannot decrypt (#299). The JWE stack lands with #298.`
    );
  }
}

/** One shipped profile, and whether THIS deployment could start on it. */
interface ProfileAvailability {
  readonly id: VerifierProfileId;
  /** `undefined` when the profile starts here; otherwise the refusal it hits. */
  readonly blockedBecause: string | undefined;
}

/**
 * Ask every shipped profile whether it would boot here, by RUNNING the guards
 * that would refuse it (#299).
 *
 * The "no profile selected" refusal used to advise, in prose, *"set it to
 * 'oid4vp-1.0-base' or 'haip-1.0'"*. Half of that was a trap: `haip-1.0` needs a
 * WRPAC no deployment can provision until #298/#233, so an operator who took the
 * second option restarted straight into a SECOND, different refusal. Two failed
 * restarts to learn that one of the two advertised values cannot start anything.
 *
 * Executing the guards rather than describing them is what keeps the advice
 * honest: the advertised set cannot drift from the set that actually boots,
 * because it IS that set, computed the same way at the same moment. When
 * #298/#233 land, `haip-1.0` moves from the blocked list to the selectable one
 * with no edit here — which is also why the blocked entry carries the refusal
 * VERBATIM rather than a summary. The operator learns the second refusal without
 * spending a restart on it.
 */
function probeProfiles(
  provisioned: ProvisionedVerifierMaterial,
  capabilities: VerifierCryptoCapabilities
): readonly ProfileAvailability[] {
  return VERIFIER_PROFILE_IDS.map((id) => {
    try {
      const candidate = resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: id }, provisioned);

      // Unreachable: `id` came from the profile table, so it always parses.
      // Reported as blocked rather than asserted away — the thing that builds an
      // error message must never become the thing that throws.
      if (candidate === undefined) {
        return { id, blockedBecause: 'the profile table does not resolve this id' };
      }

      assertProfileWithinCryptoCapabilities(candidate, capabilities);
      return { id, blockedBecause: undefined };
    } catch (error) {
      return { id, blockedBecause: error instanceof Error ? error.message : String(error) };
    }
  });
}

/**
 * Build the "wallet federation is on but no profile is selected" refusal (#299).
 *
 * Two audiences, and the text has to serve both:
 *
 *   - the operator UPGRADING an existing `WALLET_FEDERATION_ENABLED=true`
 *     deployment. They did nothing wrong and have just lost password login,
 *     `/authorize` and `/token` to a variable that did not exist in the version
 *     they were running. The message must say the requirement is NEW and name
 *     BOTH ways out, because "turn the flag back off" is the right answer for a
 *     deployment that enabled it to exercise the #232 wiring and never intended
 *     to run a wallet flow — telling them only to pick a profile would push them
 *     into an OID4VP posture decision they have no reason to make.
 *   - the operator CHOOSING a profile, who needs to know which values actually
 *     start in this deployment as configured (see {@link probeProfiles}).
 */
function buildNoProfileSelectedMessage(
  provisioned: ProvisionedVerifierMaterial,
  capabilities: VerifierCryptoCapabilities
): string {
  const availability = probeProfiles(provisioned, capabilities);
  const selectable = availability.filter((entry) => entry.blockedBecause === undefined);
  const blocked = availability.filter((entry) => entry.blockedBecause !== undefined);

  const selectableAdvice =
    selectable.length === 0
      ? 'No shipped profile can start in this deployment as it is configured, so setting OID4VP_VERIFIER_PROFILE will not help until the blockers listed below are resolved.'
      : `Set OID4VP_VERIFIER_PROFILE to one of ${quoteList(selectable.map((entry) => entry.id))} — verified startable in this deployment as it is configured right now.`;

  const blockedAdvice = blocked
    .map((entry) => `'${entry.id}' is shipped but CANNOT start here yet: ${entry.blockedBecause}`)
    .join(' ');

  return [
    'WALLET_FEDERATION_ENABLED is on but no VerifierProfile is selected.',
    'This is a NEW requirement introduced with the VerifierProfile layer (#299): a deployment that had wallet federation enabled before that layer existed now refuses to start until it states its posture, because a verifier with no declared profile has no defined posture and there is deliberately no default to fall back to (#299, #296).',
    'There are two ways to resolve it.',
    selectableAdvice,
    'Or set WALLET_FEDERATION_ENABLED=false to restore exactly the behaviour you had before upgrading — the flag gates ONLY wallet federation, so password login and OAuth come back with either fix.',
    blockedAdvice,
  ]
    .filter((part) => part !== '')
    .join(' ');
}

/**
 * Resolve the configured provider set from feature flags (ADR-003, #232).
 *
 * This is the single place where "which upstreams exist" is decided, and it is
 * a PURE function of config: no I/O, no Fastify, no database. That is
 * deliberate — it makes the flag→registry contract unit-testable without
 * booting the auth-server (which would need Postgres and Redis), so the #232
 * acceptance criteria are provable in CI rather than argued in review. It is
 * also why the crypto layer arrives as a descriptor
 * ({@link VerifierCryptoCapabilities}) instead of being probed from here.
 *
 * `PasswordProvider` is unconditional: it is the Phase 1 authentication method
 * every deployment depends on, never a flag-gated one.
 *
 * @param options - flag state, normally straight from the parsed env.
 * @returns the providers to seed the provider registry with, in registration
 * order. The registry rejects duplicate `type`s, so this list is a set by
 * construction.
 * @throws Error when wallet federation is enabled but the deployment cannot
 * operate the selected profile — see the fail-closed gate below.
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
    const provisioned = options.provisionedVerifierMaterial ?? NO_VERIFIER_MATERIAL;

    // Fail-closed verifier configuration (#299), in three questions that must
    // ALL be answered before a wallet provider may exist:
    //
    //   1. Is a profile selected?          → `resolveVerifierProfile` returns
    //                                         `undefined` when nothing usable is.
    //   2. Is its verifier identity provisionable here? → the same call THROWS;
    //      the assertion is folded into the resolver, so there is no path that
    //      obtains a `VerifierProfile` without it having been checked.
    //   3. Can our crypto layer honour its mandates? → the check below, which is
    //      the only one the resolver cannot make: it is a property of this
    //      deployment's build, not of the profile.
    //
    // The realm argument is `null`: this is the deployment-wide bootstrap
    // decision. Per-realm selection is resolved at request time by the same
    // resolver once `realms.verifier_profile` exists.
    const profile = resolveVerifierProfile(
      null,
      { OID4VP_VERIFIER_PROFILE: options.verifierProfileId },
      provisioned
    );

    if (profile === undefined) {
      throw new Error(buildNoProfileSelectedMessage(provisioned, options.cryptoCapabilities));
    }

    assertProfileWithinCryptoCapabilities(profile, options.cryptoCapabilities);

    providers.push(createWalletProvider());
  }

  return providers;
}
