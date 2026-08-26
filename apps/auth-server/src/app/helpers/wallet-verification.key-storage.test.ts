import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * `OID4VP_ATTESTING_ISSUERS` actually reaching the gate (#308/#379).
 *
 * The variable, its schema and the resolver factory are each tested where they
 * live. What only exists HERE is the WIRING — that `resolveWalletVerificationSetup`
 * hands the gate what the operator provisioned as its second half. Dropping that
 * argument still type-checks (`keyStorageAssuranceGateFor`'s resolver parameter
 * is optional, so a caller with nothing provisioned can still build a gate that
 * keeps its posture), still leaves every other case in this package passing, and
 * silently reverts #379: the gate falls back to
 * `DENY_ALL_KEY_STORAGE_ASSURANCE_RESOLVER` and establishes nothing for anyone.
 * That is Break 1 restored.
 *
 * ## Why a separate file
 *
 * The resolver is memoized at module scope — built once per process, as a
 * factory that validates every entry eagerly and throws on a malformed one must
 * be. So the deployment's attesting-issuer record has to be in place before the
 * first `resolveWalletVerificationSetup` call in the module's life, which means
 * before any other suite runs. Re-instantiating the module instead is not an
 * option: `vi.resetModules()` would need `@qauth-labs/fastify-plugin-federation`
 * re-imported from the same fresh graph to keep the `ValidatedIssuer` brand
 * comparable, and a dynamic import of a workspace library marks that library
 * lazy-loaded for the whole workspace (`@nx/enforce-module-boundaries`).
 *
 * One record with THREE issuers covers the cases a per-test record would have,
 * and covers them better: "not recorded" and "recorded too weakly" are then
 * distinguished inside a single deployment rather than across two.
 *
 * ## Why the posture is stated rather than taken from the active profile
 *
 * `oid4vp-1.0-base` declares `keyStorageAssurance: 'forbidden'`, and a forbidden
 * posture returns before the resolver is consulted at all — so on the only
 * profile that boots today a wired resolver and a deny-all are
 * indistinguishable. The posture below is `haip-1.0`'s pair verbatim
 * (`required` + `iso_18045_high`), written as a literal because
 * `resolveVerifierProfile('haip-1.0')` refuses for an unrelated reason (#299
 * X.509 material, pending #233) and this suite is not about that refusal.
 */

/** Recorded as attesting at the grade `haip-1.0` mandates. */
const STRONG_ISSUER = 'https://strong.issuer.example';
/** Recorded as attesting, but below that grade. */
const WEAK_ISSUER = 'https://weak.issuer.example';
/** Not recorded at all — the state of every issuer in an unconfigured deployment. */
const UNRECORDED_ISSUER = 'https://unrecorded.issuer.example';

const { envMock } = vi.hoisted(() => ({
  envMock: {
    WALLET_FEDERATION_ENABLED: true,
    JWT_ISSUER: 'https://auth.example.com',
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' as string | undefined,
    // The verifier-identity variables at their parsed DEFAULTS (#377). Stated
    // rather than omitted because the request path now resolves the profile with
    // the deployment's provisioned material, and
    // `resolveVerifierCertificateChainPems` reads `.length` off the array forms —
    // which the real parsed env always supplies (Zod defaults them to `[]`) and
    // an env stub silently would not.
    OID4VP_VERIFIER_SIGNING_KEY: undefined as string | undefined,
    OID4VP_VERIFIER_SIGNING_KEY_PATH: undefined as string | undefined,
    OID4VP_VERIFIER_CERTIFICATE_CHAIN: [] as readonly string[],
    OID4VP_VERIFIER_CERTIFICATE_CHAIN_PATH: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS: [] as readonly string[],
    OID4VP_VERIFIER_TRUST_ANCHORS_PATH: [] as readonly string[],
    OID4VP_REQUESTED_VCT: ['urn:example:pid'] as readonly string[] | undefined,
    OID4VP_WALLET_INVOCATION_ENDPOINT: 'openid4vp://',
    OID4VP_SUBJECT_RESOLUTION: undefined as string | undefined,
    OID4VP_SUBJECT_BINDING_CLAIMS: ['given_name'] as readonly string[] | undefined,
    OID4VP_SUBJECT_CLAIM: undefined as string | undefined,
    OID4VP_SUBJECT_CLAIM_ISSUERS: undefined as readonly string[] | undefined,
    OID4VP_TRUSTED_ISSUERS: {} as Record<string, readonly string[]>,
    OID4VP_ISSUER_JWKS: {} as Record<string, readonly Record<string, unknown>[]>,
    OID4VP_STATUS_LIST_TRUST_ANCHORS: [] as readonly string[],
    OID4VP_STATUS_LIST_TRUST_ANCHORS_PATH: [] as readonly string[],
    OID4VP_STATUS_LIST_URI_ALLOWLIST: [] as readonly string[],
    // Set once, before the module under test is ever called, for the memoization
    // reason in this file's header.
    OID4VP_ATTESTING_ISSUERS: {
      'https://strong.issuer.example': 'iso_18045_high',
      'https://weak.issuer.example': 'iso_18045_basic',
    } as Record<string, string>,
  },
}));

vi.mock('../../config/env', () => ({ env: envMock }));

import { ValidatedIssuer } from '@qauth-labs/fastify-plugin-federation';

import { resolveWalletVerificationSetup } from './wallet-verification';

/** A P-256 holder key. Never consulted on the transitive path; the type wants it. */
const CONFIRMATION_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
};

function makeFastify(): FastifyInstance {
  return {
    repositories: { realms: { findById: vi.fn().mockResolvedValue(undefined) } },
    log: { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() },
  } as unknown as FastifyInstance;
}

/** Ask the deployment's own gate what it establishes for one issuer. */
function decisionFor(issuer: string) {
  const setup = resolveWalletVerificationSetup(makeFastify());
  if (setup === undefined) throw new Error('the deployment resolved no wallet setup');

  return setup.keyStorageAssurance.resolver.resolveKeyStorageAssurance(
    {
      // Branded for real: the registry re-checks `ValidatedIssuer.isValidated`
      // itself, so a hand-built issuer object would be refused whatever
      // identifier it carried and every case here would pass for the wrong
      // reason.
      issuer: ValidatedIssuer.fromValidatedPresentation({
        identifier: issuer,
        keyResolution: 'issuer-metadata',
      }),
      confirmationJwk: CONFIRMATION_JWK,
      claims: {},
    },
    { posture: 'required', minimumAttackPotential: 'iso_18045_high' }
  );
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('the key-storage assurance gate carries the deployment resolver (#308/#379)', () => {
  it('establishes the recorded grade for an issuer the operator provisioned', async () => {
    await expect(decisionFor(STRONG_ISSUER)).resolves.toEqual({
      outcome: 'accepted',
      evidence: { assurance: 'issuer-attested', keyStorage: 'iso_18045_high' },
    });
  });

  it('establishes NOTHING for an issuer the operator did not record', async () => {
    // Asserted by REASON rather than by "it did not accept": a rejection for the
    // wrong reason would mean the resolver is refusing something other than an
    // absence, and a fail-closed test that cannot tell those apart stops testing
    // what it names.
    await expect(decisionFor(UNRECORDED_ISSUER)).resolves.toEqual({
      outcome: 'rejected',
      reason: 'assurance-required-but-absent',
    });
  });

  it('refuses a recorded grade below what the posture mandates', async () => {
    // Provisioning an issuer is not the same as clearing the bar. The record is
    // read, ranked and refused — never rounded up — and the reason differs from
    // the absence above, which is what an operator needs to tell "I forgot this
    // issuer" from "this issuer is not good enough".
    await expect(decisionFor(WEAK_ISSUER)).resolves.toEqual({
      outcome: 'rejected',
      reason: 'attack-potential-below-minimum',
    });
  });
});
