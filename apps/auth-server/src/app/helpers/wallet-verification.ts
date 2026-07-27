import {
  createConfiguredIssuerKeyResolver,
  type IssuerKeyResolver,
  resolveSubjectResolution,
  resolveTrustRegistry,
  type SubjectResolutionConfig,
  type TrustRegistry,
  type VerifierProfile,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';
import { resolveWalletLoginCapability } from './wallet-login-request';

/**
 * The deployment's wallet VERIFICATION posture, resolved per request
 * (issue #238; composes #234, #236, #299 and #300).
 *
 * Three independent decisions have to line up before a presented credential can
 * become anything, and each one is configured separately on purpose:
 *
 * | question | source |
 * | --- | --- |
 * | what protocol posture do we run? | `VerifierProfile` (#299) |
 * | which key does an issuer sign with? | `OID4VP_ISSUER_JWKS` (#234) |
 * | which issuers does this realm accept? | `OID4VP_TRUSTED_ISSUERS` (#236) |
 * | which account does a credential belong to? | `OID4VP_SUBJECT_RESOLUTION` (#300) |
 *
 * Resolving them in ONE place is what keeps the login flow and the linking flow
 * (#238) from drifting into two different postures — the drift that
 * `resolveVerifierProfile` and `resolveTrustRegistry` each exist to prevent
 * within their own question.
 *
 * ## Fail-closed, and two distinguishable ways
 *
 * `undefined` means *this deployment cannot serve wallet flows* — no profile, no
 * requested `vct`, a posture needing capabilities that are not there. Callers
 * turn it into "wallet sign-in is not available", never into a permissive
 * fallback (#296, LOCKED).
 *
 * A THROW means the deployment is half-configured: a strategy was selected and
 * its settings are missing or unusable. `resolveSubjectResolution` is explicit
 * about where that lands — a deployment that configures nothing gets
 * `asserted-lookup` from the profile and then a throw, because it named no
 * binding claims, and *"`asserted-lookup` without an entitlement check is
 * ADR-009 §1's total authentication bypass"*. Callers surface it as an operator
 * error; they must not degrade it to "no wallet login today", because that would
 * make a misconfiguration look like an intentional opt-out.
 */

/** Everything the verification path needs, resolved together. */
export interface WalletVerificationSetup {
  /** The active `VerifierProfile` (#299). */
  readonly profile: VerifierProfile;
  /** The realm's subject-resolution configuration (#300). */
  readonly subjectResolution: SubjectResolutionConfig;
  /** The configured issuer key backend (#234). */
  readonly resolveIssuerKey: IssuerKeyResolver;
}

/**
 * The issuer key resolver, built ONCE.
 *
 * `createStaticIssuerKeyResolver` validates every entry eagerly and throws on a
 * malformed one, which is right at bootstrap and wrong per request. Memoized
 * rather than module-initialised so importing this file cannot take the process
 * down for a deployment that never enables wallet federation — and so the tests
 * that stub `env` are not fighting an import-time side effect.
 */
let cachedIssuerKeyResolver: IssuerKeyResolver | undefined;

function issuerKeyResolver(): IssuerKeyResolver {
  cachedIssuerKeyResolver ??= createConfiguredIssuerKeyResolver(env.OID4VP_ISSUER_JWKS);
  return cachedIssuerKeyResolver;
}

/**
 * Resolve the deployment's wallet verification posture.
 *
 * @param fastify - server instance, for logging.
 * @returns the setup, or `undefined` when wallet flows must not be served.
 * @throws InvalidConfigurationError when a subject-resolution strategy is
 * selected but half-configured.
 */
export function resolveWalletVerificationSetup(
  fastify: FastifyInstance
): WalletVerificationSetup | undefined {
  const capability = resolveWalletLoginCapability(fastify);
  if (capability === undefined) return undefined;

  // The realm argument is null because `realms.subject_resolution` does not
  // exist yet (#300) — the same call shape `resolveVerifierProfile` is given
  // everywhere else, so per-realm selection lands in one edit.
  const subjectResolution = resolveSubjectResolution(null, env, capability.profile);
  if (subjectResolution === undefined) {
    fastify.log.warn(
      'wallet flows unavailable: no usable subject-resolution strategy is selected (#300)'
    );
    return undefined;
  }

  return {
    profile: capability.profile,
    subjectResolution,
    resolveIssuerKey: issuerKeyResolver(),
  };
}

/**
 * Resolve the issuer allowlist in force for a realm (#236).
 *
 * Keyed by `realms.name`, which is what `OID4VP_TRUSTED_ISSUERS` is authored
 * against — realm ids are database-minted UUIDs an operator cannot know when
 * writing configuration.
 *
 * @param fastify - server instance, for its repositories.
 * @param realmId - the realm the presentation request was created in.
 * @returns the realm's registry. NEVER `undefined` and never permissive: a realm
 * that cannot be read at all resolves to trusting nobody, which refuses every
 * presentation rather than accepting one from an unknown policy.
 */
export async function resolveRealmTrustRegistry(
  fastify: FastifyInstance,
  realmId: string
): Promise<TrustRegistry> {
  let realmName: string | null = null;
  try {
    const realm = await fastify.repositories.realms.findById(realmId);
    realmName = realm?.name ?? null;
  } catch (error) {
    // Contained: an unreadable realm must land on deny-all, not on a 500 that
    // an attacker can tell apart from a refusal.
    fastify.log.error({ err: error, realmId }, 'failed to read the realm for its issuer allowlist');
  }

  return resolveTrustRegistry(
    { name: realmName },
    { OID4VP_TRUSTED_ISSUERS: env.OID4VP_TRUSTED_ISSUERS }
  );
}
