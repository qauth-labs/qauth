import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it, vi } from 'vitest';

// `verifier-identity.ts` imports the parsed `env` at module scope for its cached
// entry point. These tests exercise the PURE reconciliation function instead, so
// the module-scope parse is stubbed away rather than satisfied — a unit test of
// the rules must not need a whole valid environment.
vi.mock('../../config/env', () => ({ env: {} }));

import { createMockVerifierPki, type MockVerifierPki } from '../../testing/mock-verifier-pki';
import {
  assertStoredVerifierKeyMatchesChain,
  resolveConfiguredVerifierSigningMaterial,
  type VerifierCertificateEnvLike,
} from './verifier-identity';

/**
 * Reconciling the verifier's public variables into ONE answer (issue #377,
 * Phase A; #546).
 *
 * The interesting property is the middle case. "Everything set" and "nothing
 * set" are both real answers a deployment can hold; every state between them is
 * an operator who INTENDED to provision a verifier identity and did not finish,
 * and reading that as "nothing is configured" would take the deployment down the
 * unsigned path with a weaker identity than the operator believed they had —
 * the half-configured verifier #299 forbids.
 *
 * The key is not among the variables (#546): the signer's key boot step
 * imports it, and the boot checks the stored key's public half against the
 * chain ({@link assertStoredVerifierKeyMatchesChain}).
 */

const pki = createMockVerifierPki();

/** The parsed public verifier variables, every one unset. */
const NOTHING: VerifierCertificateEnvLike = Object.freeze({
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

const FULLY_CONFIGURED: VerifierCertificateEnvLike = Object.freeze({
  ...NOTHING,
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

  it('holds no private key (#546)', () => {
    const material = resolveConfiguredVerifierSigningMaterial(FULLY_CONFIGURED);
    expect(JSON.stringify(material)).not.toContain('PRIVATE KEY');
    expect(material && 'privateKeyPem' in material).toBe(false);
  });

  it('refuses an anchor with no chain — a partial state, not "nothing"', () => {
    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...NOTHING,
        OID4VP_VERIFIER_TRUST_ANCHORS: blocks(pki.trustAnchorPem),
      })
    ).toThrow(InvalidConfigurationError);
  });

  it('refuses a chain with no anchor', () => {
    expect(() =>
      resolveConfiguredVerifierSigningMaterial({
        ...FULLY_CONFIGURED,
        OID4VP_VERIFIER_TRUST_ANCHORS: [],
      })
    ).toThrow(/no trust anchor is/);
  });

  it('reads the chain and anchors from either source', () => {
    const fromPath = resolveConfiguredVerifierSigningMaterial({
      ...NOTHING,
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

/** The leaf key of `of` as the signer's `getVerificationKeys` lists it. */
function storedKey(
  of: MockVerifierPki,
  overrides: { readonly kid?: string; readonly status?: 'active' | 'retired' } = {}
) {
  const kid = overrides.kid ?? 'request-key';
  return {
    kid,
    algorithm: 'ES256',
    status: overrides.status ?? ('active' as const),
    publicJwk: { ...of.leaf.publicKey.export({ format: 'jwk' }), kid, alg: 'ES256', use: 'sig' },
  };
}

describe('assertStoredVerifierKeyMatchesChain (#546)', () => {
  const material = resolveConfiguredVerifierSigningMaterial(FULLY_CONFIGURED);
  const other = createMockVerifierPki({ name: 'other.example' });

  it('answers nothing, and refuses nothing, when no chain is configured', () => {
    expect(assertStoredVerifierKeyMatchesChain(undefined, [])).toEqual([]);
    expect(assertStoredVerifierKeyMatchesChain(undefined, [storedKey(pki)])).toEqual([]);
  });

  it('answers ES256 when an active stored key is the one the leaf names', () => {
    expect(assertStoredVerifierKeyMatchesChain(material, [storedKey(pki)])).toEqual(['ES256']);
    expect(
      assertStoredVerifierKeyMatchesChain(material, [
        storedKey(other, { kid: 'other' }),
        storedKey(pki),
      ])
    ).toEqual(['ES256']);
  });

  it('refuses a chain when the store holds no request key', () => {
    expect(() => assertStoredVerifierKeyMatchesChain(material, [])).toThrow(
      /holds no OID4VP request key/
    );
  });

  it('refuses a chain whose leaf names no active stored key, naming the kids', () => {
    try {
      assertStoredVerifierKeyMatchesChain(material, [storedKey(other, { kid: 'other' })]);
      expect.unreachable('a chain of another key must refuse the boot');
    } catch (error) {
      expect(error).toBeInstanceOf(InvalidConfigurationError);
      expect((error as Error).message).toMatch(/does not name/);
      expect((error as InvalidConfigurationError).details).toEqual({ activeKids: ['other'] });
    }
  });

  it('does not count a retired key: a retired key signs nothing', () => {
    expect(() =>
      assertStoredVerifierKeyMatchesChain(material, [storedKey(pki, { status: 'retired' })])
    ).toThrow(/holds no OID4VP request key/);
  });
});
