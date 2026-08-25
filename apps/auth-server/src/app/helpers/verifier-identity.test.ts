import type { VerifierSigningEnvLike } from '@qauth-labs/server-config';
import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

// `verifier-identity.ts` imports the parsed `env` at module scope for its cached
// entry point. These tests exercise the PURE reconciliation function instead, so
// the module-scope parse is stubbed away rather than satisfied — a unit test of
// the rules must not need a whole valid environment.
vi.mock('../../config/env', () => ({ env: {} }));

import { createMockVerifierPki } from '../../testing/mock-verifier-pki';
import { resolveConfiguredVerifierSigningMaterial } from './verifier-identity';

/**
 * Reconciling three independent variables into ONE answer (issue #377, Phase A).
 *
 * The interesting property is the middle case. "Everything set" and "nothing
 * set" are both real answers a deployment can hold; every state between them is
 * an operator who INTENDED to provision a verifier identity and did not finish,
 * and reading that as "nothing is configured" would take the deployment down the
 * unsigned path with a weaker identity than the operator believed they had —
 * the half-configured verifier #299 forbids.
 */

const pki = createMockVerifierPki();

/** The parsed federation env, with every verifier variable unset. */
const NOTHING: VerifierSigningEnvLike = Object.freeze({
  OID4VP_VERIFIER_SIGNING_KEY: undefined,
  OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined,
  OID4VP_VERIFIER_CERTIFICATE_CHAIN: [],
  OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [],
  OID4VP_VERIFIER_TRUST_ANCHORS: [],
  OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [],
});

/** Split a concatenated PEM bundle the way the env schema does. */
function blocks(bundle: string): readonly string[] {
  return (bundle.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? []).map(
    (pem) => pem.trim()
  );
}

const FULLY_CONFIGURED: VerifierSigningEnvLike = Object.freeze({
  ...NOTHING,
  OID4VP_VERIFIER_SIGNING_KEY: pki.signingKeyPem,
  OID4VP_VERIFIER_CERTIFICATE_CHAIN: blocks(pki.certificateChainPem),
  OID4VP_VERIFIER_TRUST_ANCHORS: blocks(pki.trustAnchorPem),
});

describe('resolveConfiguredVerifierSigningMaterial (#377)', () => {
  it('resolves a fully configured deployment to validated material', () => {
    const material = resolveConfiguredVerifierSigningMaterial(FULLY_CONFIGURED);

    expect(material?.x5c).toEqual([pki.leaf.x5c, pki.intermediate.x5c]);
    expect(material?.x5c).not.toContain(pki.anchor.x5c);
  });

  it('resolves an unconfigured deployment to NOTHING, without a boot failure', () => {
    // The default posture of every deployment running `oid4vp-1.0-base` or no
    // wallet federation at all. It must not cost them a boot.
    expect(resolveConfiguredVerifierSigningMaterial(NOTHING)).toBeUndefined();
  });

  it('refuses certificate material with no key', () => {
    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...FULLY_CONFIGURED,
        OID4VP_VERIFIER_SIGNING_KEY: undefined,
      })
    ).toThrow(InvalidConfigurationError);
  });

  it('names the variable to set when only the key is missing', () => {
    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...FULLY_CONFIGURED,
        OID4VP_VERIFIER_SIGNING_KEY: undefined,
      })
    ).toThrow(/OID4VP_VERIFIER_SIGNING_KEY/);
  });

  it('refuses an anchor with no key or chain — a partial state, not "nothing"', () => {
    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...NOTHING,
        OID4VP_VERIFIER_TRUST_ANCHORS: blocks(pki.trustAnchorPem),
      })
    ).toThrow(/OID4VP_VERIFIER_SIGNING_KEY/);
  });

  it('refuses a key with no chain', () => {
    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...NOTHING,
        OID4VP_VERIFIER_SIGNING_KEY: pki.signingKeyPem,
      })
    ).toThrow(/no certificate chain is/);
  });

  it('refuses a chain with no anchor', () => {
    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...FULLY_CONFIGURED,
        OID4VP_VERIFIER_TRUST_ANCHORS: [],
      })
    ).toThrow(/no trust anchor is/);
  });

  it('reads the key from either source', () => {
    const fromPath = resolveConfiguredVerifierSigningMaterial({
      ...FULLY_CONFIGURED,
      OID4VP_VERIFIER_SIGNING_KEY: undefined,
      OID4VP_VERIFIER_SIGNING_KEY_PATH: pki.signingKeyPem,
    });

    expect(fromPath?.x5c).toEqual([pki.leaf.x5c, pki.intermediate.x5c]);
  });

  it('reads the chain and anchors from either source', () => {
    const fromPath = resolveConfiguredVerifierSigningMaterial({
      ...NOTHING,
      OID4VP_VERIFIER_SIGNING_KEY: pki.signingKeyPem,
      OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: blocks(pki.certificateChainPem),
      OID4VP_VERIFIER_TRUST_ANCHORS_PATH: blocks(pki.trustAnchorPem),
    });

    expect(fromPath?.x5c).toEqual([pki.leaf.x5c, pki.intermediate.x5c]);
  });

  it('delegates chain validation rather than restating it', () => {
    // A chain that reaches an anchor nobody configured is refused by
    // `createVerifierSigningMaterial`, with its own reason on `details`. This
    // asserts the delegation happens at all — a version of this function that
    // only checked presence would resolve happily here.
    const stranger = createMockVerifierPki({ name: 'stranger.example' });

    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...FULLY_CONFIGURED,
        OID4VP_VERIFIER_TRUST_ANCHORS: blocks(stranger.trustAnchorPem),
      })
    ).toThrow(InvalidConfigurationError);
  });
});
