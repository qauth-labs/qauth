import {
  createVerifierSigningMaterial,
  type VerifierSigningMaterial,
} from '@qauth-labs/fastify-plugin-federation';
import {
  resolveVerifierCertificateChainPems,
  resolveVerifierSigningKeyPem,
  resolveVerifierTrustAnchorPems,
  type VerifierSigningEnvLike,
} from '@qauth-labs/server-config';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';

import { env } from '../../config/env';

/**
 * The deployment's OID4VP VERIFIER identity, resolved from configuration
 * (issue #377, Phase A).
 *
 * Three variables and one answer. `OID4VP_VERIFIER_SIGNING_KEY`, its certificate
 * chain and its trust anchors are separate settings an operator can get
 * independently wrong, and this is the one place they are reconciled into
 * either "a validated identity" or "none" — with every partial state in
 * between refused rather than silently treated as one of the two.
 *
 * ## Why partial configuration is a REFUSAL, not "no identity"
 *
 * A key with no chain, or a chain with no anchor, is an operator who INTENDED to
 * provision a verifier identity and did not finish. Reading that as "nothing is
 * configured" would take the deployment down the unsigned path — which under a
 * profile that permits it would work, quietly, with a weaker verifier identity
 * than the operator believed they had configured. That is the half-configured
 * verifier #299 forbids, so it fails the boot instead.
 *
 * Unset EVERYTHING, on the other hand, is a real and common answer: it is the
 * default posture of every deployment that runs `oid4vp-1.0-base` or no wallet
 * federation at all, and it must not cost them a boot.
 *
 * ## Why it is cached
 *
 * `createVerifierSigningMaterial` parses certificates and verifies a chain — not
 * expensive, but not free either, and doing it per request would make a wallet
 * login's cost depend on the chain's length. It is also, deliberately, a value
 * that cannot change while the process runs: the boot either accepted this
 * material or refused to start, so re-reading it later could only ever produce
 * the same answer or an inconsistency.
 */

/** Nothing resolved yet. Distinguished from "resolved to `undefined`". */
let resolved: { readonly material: VerifierSigningMaterial | undefined } | undefined;

/**
 * Resolve the verifier signing material from parsed federation configuration.
 *
 * Exported separately from {@link verifierSigningMaterial} so the reconciliation
 * rules are provable in a unit test that does not need a whole environment —
 * the same property `deriveCryptoCapabilities` is built around.
 *
 * @param federationEnv - the parsed `OID4VP_VERIFIER_*` variables.
 * @returns the validated material, or `undefined` when the deployment
 * provisioned no verifier identity at all.
 * @throws InvalidConfigurationError when the configuration is PARTIAL, or when
 * the chain does not validate against the configured anchors.
 */
export function resolveConfiguredVerifierSigningMaterial(
  federationEnv: VerifierSigningEnvLike
): VerifierSigningMaterial | undefined {
  const privateKeyPem = resolveVerifierSigningKeyPem(federationEnv);
  const certificateChainPems = resolveVerifierCertificateChainPems(federationEnv);
  const trustAnchorPems = resolveVerifierTrustAnchorPems(federationEnv);

  const configuredNothing =
    privateKeyPem === undefined &&
    certificateChainPems.length === 0 &&
    trustAnchorPems.length === 0;

  if (configuredNothing) return undefined;

  if (privateKeyPem === undefined) {
    throw new InvalidConfigurationError(
      'OID4VP verifier certificate material is configured but OID4VP_VERIFIER_SIGNING_KEY (or its _PATH form) is not (#377). A chain identifies a key; without the key there is nothing to sign an Authorization Request with. Configure the key, or unset the certificate variables to run the unsigned path deliberately.'
    );
  }

  // Every remaining rule — chain present, anchors present, chain anchored, key
  // belongs to the leaf — belongs to `createVerifierSigningMaterial`, which is
  // where the X.509 questions are already answered for the two OTHER trust
  // directions. Restating any of them here would be a second rule set on a drift
  // course with the first.
  return createVerifierSigningMaterial({
    privateKeyPem,
    certificateChainPems,
    trustAnchorPems,
  });
}

/**
 * The deployment's verifier signing material, resolved once.
 *
 * @returns the validated material, or `undefined` when none is configured.
 * @throws InvalidConfigurationError on a partial or invalid configuration — at
 * BOOT, because `app.ts` calls this during plugin registration.
 */
export function verifierSigningMaterial(): VerifierSigningMaterial | undefined {
  resolved ??= { material: resolveConfiguredVerifierSigningMaterial(env) };
  return resolved.material;
}
