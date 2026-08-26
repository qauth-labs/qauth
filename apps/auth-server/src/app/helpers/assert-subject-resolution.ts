import {
  type ProvisionedVerifierMaterial,
  resolveSubjectResolution,
  resolveVerifierProfile,
  type VerifierProfile,
} from '@qauth-labs/fastify-plugin-federation';

import { env } from '../../config/env';

/**
 * Refuse, at BOOT, a wallet deployment with no usable subject-resolution
 * strategy (issue #379 D2, ADR-010 §6; closes the deferrals in #300 and #238).
 *
 * ## Why the deferral expired
 *
 * #300 and #238 each shipped without this gate, both recording the same reason:
 * *"Nothing consumes the strategy today … it belongs with the first consumer."*
 * The consumer now exists — `routes/ui/wallet-login.ts` calls
 * `resolveWalletPresentation`, which builds the strategy for real — so the
 * premise is gone.
 *
 * ## What a half-configured deployment did instead
 *
 * `resolveSubjectResolution` threw `InvalidConfigurationError` on every
 * presentation; `wallet-presentation.ts` caught it, logged at `error`, and
 * returned the same uniform `{ status: 'rejected' }` a forged credential gets.
 * That is correct ON THE WIRE — an anonymous caller must not be able to tell a
 * misconfiguration from a rejection — and wrong as an operator's ONLY discovery
 * channel, because the symptom is a 100% login-failure rate with no configuration
 * error anywhere.
 *
 * This gate replaces the discovery channel and **changes nothing about the wire**.
 * The request-path catch stays exactly as it is; see `wallet-presentation.ts`.
 *
 * ## Where it lives, and why not inside `createConfiguredProviders`
 *
 * Beside `assertTrustedIssuersUsable` in `app.ts`, for the reason that function
 * gives for itself: *"finding it at boot beats finding it when the first
 * presentation arrives."* Not inside `createConfiguredProviders`, which is a
 * pure function of its options and knows nothing about `OID4VP_SUBJECT_*` — the
 * option it would take is a boolean the bootstrap has to compute anyway, and
 * computing it would throw away the message that names the variable to set.
 *
 * It reuses `resolveSubjectResolution` as the single authority. A second
 * implementation of "is this configuration usable" would be free to drift from
 * the one the request path actually runs, which is the failure mode a boot gate
 * is supposed to prevent rather than introduce.
 *
 * ## This IS a breaking change, deliberately
 *
 * `WALLET_FEDERATION_ENABLED=true` with no `OID4VP_SUBJECT_*` variables booted
 * before this, and `.env.example` shipped both commented out, so it was the
 * documented default shape. That deployment already refused every presentation:
 * the profile default is `asserted-lookup`, and an unconfigured `asserted-lookup`
 * has no binding claims to check, which ADR-009 §1 calls a total authentication
 * bypass. It simply learned about it from failed logins rather than from a
 * failed start. `.env.example` and `docs/wallet-login.md` present the variables
 * as required when wallet federation is on.
 */

/**
 * Resolve the profile the way the request path does, or give up quietly.
 *
 * A profile that cannot resolve is NOT this gate's business, and refusing here
 * would take the boot down with the wrong message. `createConfiguredProviders`
 * — registered a few lines later in `app.ts` — is the authority on profile
 * usability and produces a refusal naming the profile and the unmet capability.
 * Pre-empting it would replace *"verifier profile 'haip-1.0' requires …"* with a
 * complaint about a subject-resolution variable, which is neither the operator's
 * first problem nor a message they could act on.
 */
function resolvableProfile(
  environment: SubjectResolutionBootEnv,
  provisioned?: ProvisionedVerifierMaterial
): VerifierProfile | undefined {
  try {
    // The realm argument is null because `realms.verifier_profile` does not
    // exist yet (#299) — the same call shape every other consumer uses.
    //
    // `provisioned` is forwarded rather than defaulted so this resolves exactly
    // the profiles `createConfiguredProviders` resolves. Letting it default here
    // while the provider path received real material would make this function
    // return `undefined` for an x509 profile that boots fine, and the caller
    // treats `undefined` as "nothing to check".
    return resolveVerifierProfile(
      null,
      { OID4VP_VERIFIER_PROFILE: environment.OID4VP_VERIFIER_PROFILE },
      provisioned
    );
  } catch {
    return undefined;
  }
}

/** The environment members this gate reads. */
export interface SubjectResolutionBootEnv {
  readonly WALLET_FEDERATION_ENABLED: boolean;
  readonly OID4VP_VERIFIER_PROFILE?: string | undefined;
  readonly OID4VP_SUBJECT_RESOLUTION?: string | undefined;
  readonly OID4VP_SUBJECT_BINDING_CLAIMS?: readonly string[] | undefined;
  readonly OID4VP_SUBJECT_CLAIM?: string | undefined;
  readonly OID4VP_SUBJECT_CLAIM_ISSUERS?: readonly string[] | undefined;
}

/**
 * Assert this deployment can resolve a presented credential to an account.
 *
 * A no-op unless `WALLET_FEDERATION_ENABLED` is on. Unlike
 * `assertTrustedIssuersUsable` next door, this one IS gated on the flag: an
 * allowlist typo is a typo whether or not wallet flows are switched on, but
 * "you configured no subject-resolution strategy" is not a defect in a
 * deployment that runs no wallet flows — it is the correct state, and refusing
 * it would make the flag unusable as an off switch.
 *
 * @param environment - the parsed environment (defaults to the process env).
 * @param provisioned - the deployment's X.509 verifier material, from `app.ts`'s
 * single `PROVISIONED_VERIFIER_MATERIAL` constant. It MUST be the same value
 * `createConfiguredProviders` receives: this gate returns early when no profile
 * resolves, so material that made a profile resolvable there but not here would
 * switch the gate off without a word. `undefined` until #233.
 * @throws InvalidConfigurationError when a strategy is selected — including by
 * the profile's own default — and its required settings are missing or unusable.
 * The message comes from `resolveSubjectResolution` verbatim and names the
 * variable to set.
 * @throws Error when nothing usable is selected at all.
 */
export function assertSubjectResolutionProvisioned(
  environment: SubjectResolutionBootEnv = env,
  provisioned?: ProvisionedVerifierMaterial
): void {
  if (!environment.WALLET_FEDERATION_ENABLED) return;

  const profile = resolvableProfile(environment, provisioned);
  if (profile === undefined) return;

  // Throws for the half-configured case, which is the whole point, and the
  // message travels untouched — `normalizeBindingClaims` already names
  // OID4VP_SUBJECT_BINDING_CLAIMS and explains that with no binding claims any
  // valid credential would authenticate any account.
  const resolved = resolveSubjectResolution(null, environment, profile);

  // `undefined` means nothing usable was SELECTED, which
  // `resolveSubjectResolution` documents as a distinct answer from a throw: the
  // caller decides what it means, and for a bootstrap it means refuse. Reached
  // only if a profile ever declares no default strategy — today every profile
  // does — so this is the branch that keeps a future profile from booting into a
  // deployment that silently serves no wallet login.
  if (resolved === undefined) {
    throw new Error(
      `WALLET_FEDERATION_ENABLED is on and verifier profile '${profile.id}' selects no usable subject-resolution strategy. Set OID4VP_SUBJECT_RESOLUTION (with OID4VP_SUBJECT_BINDING_CLAIMS, and OID4VP_SUBJECT_CLAIM / OID4VP_SUBJECT_CLAIM_ISSUERS for 'issuer-scoped-claim'), or turn WALLET_FEDERATION_ENABLED off. Refusing to start rather than accepting wallet requests and then rejecting every presentation (#300, #379).`
    );
  }
}
