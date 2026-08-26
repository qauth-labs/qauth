import { describe, expect, it, vi } from 'vitest';

/**
 * The subject-resolution BOOT gate (issue #379 D2, ADR-010 §6).
 *
 * #300 and #238 each deferred this gate "to the first consumer" because nothing
 * consumed the strategy; the wallet login path now does. What is asserted here
 * is the predicate itself — the integration suite
 * (`wallet-subject-resolution-boot.integration.test.ts`) proves the same
 * behaviour through a real `buildApp`.
 *
 * The env module is mocked only so the default parameter has something to
 * resolve; every assertion passes its environment explicitly, because a gate
 * whose behaviour depended on ambient process state would be exactly as hard to
 * reason about as the misconfiguration it exists to surface.
 */

vi.mock('../../config/env', () => ({ env: { WALLET_FEDERATION_ENABLED: false } }));

// Imported AFTER the mock, as every suite in this directory does: `vi.mock` is
// hoisted, but keeping the import here makes the ordering requirement visible.
import { assertSubjectResolutionProvisioned } from './assert-subject-resolution';

/** A deployment with wallet federation on and the base profile selected. */
function walletOn(overrides: Record<string, unknown> = {}) {
  return {
    WALLET_FEDERATION_ENABLED: true,
    OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base',
    ...overrides,
  } as Parameters<typeof assertSubjectResolutionProvisioned>[0];
}

describe('assertSubjectResolutionProvisioned — refuses the half-configured shape', () => {
  it('refuses an enabled deployment that names no binding claims', () => {
    // THE breaking change. `.env.example` shipped both OID4VP_SUBJECT_*
    // variables commented out, so this was the documented default shape and it
    // booted. It also refused every presentation, because the profile default is
    // `asserted-lookup` and an `asserted-lookup` with no binding claims is
    // ADR-009 §1's total authentication bypass.
    expect(() => assertSubjectResolutionProvisioned(walletOn())).toThrow();
  });

  it('names the variable an operator has to set', () => {
    // A boot refusal that does not say what to set is a worse discovery channel
    // than the 100% login-failure rate it replaced.
    expect(() => assertSubjectResolutionProvisioned(walletOn())).toThrow(
      /OID4VP_SUBJECT_BINDING_CLAIMS/
    );
  });

  it('surfaces the real InvalidConfigurationError message, not a boolean of it', () => {
    // D2 chose the app.ts placement over a boolean option threaded into
    // `createConfiguredProviders` precisely so this text survives.
    expect(() => assertSubjectResolutionProvisioned(walletOn())).toThrow(
      /at least one credential claim/
    );
  });

  it("refuses 'issuer-scoped-claim' with no subject claim, naming that variable", () => {
    expect(() =>
      assertSubjectResolutionProvisioned(
        walletOn({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_BINDING_CLAIMS: ['family_name', 'given_name'],
        })
      )
    ).toThrow(/OID4VP_SUBJECT_CLAIM/);
  });

  it("refuses 'issuer-scoped-claim' with a claim but no issuers", () => {
    expect(() =>
      assertSubjectResolutionProvisioned(
        walletOn({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_BINDING_CLAIMS: ['family_name', 'given_name'],
          OID4VP_SUBJECT_CLAIM: 'personal_administrative_number',
        })
      )
    ).toThrow(/OID4VP_SUBJECT_CLAIM_ISSUERS/);
  });

  it('refuses a binding claim ADR-009 §2 forbids', () => {
    // The gate runs the REAL resolver, so every refusal the request path would
    // have raised is raised at boot instead — including the ones that are not
    // about a missing variable.
    expect(() =>
      assertSubjectResolutionProvisioned(walletOn({ OID4VP_SUBJECT_BINDING_CLAIMS: ['iss'] }))
    ).toThrow();
  });
});

describe('assertSubjectResolutionProvisioned — what it must NOT refuse', () => {
  it('accepts a fully configured asserted-lookup deployment', () => {
    expect(() =>
      assertSubjectResolutionProvisioned(
        walletOn({ OID4VP_SUBJECT_BINDING_CLAIMS: ['family_name', 'given_name', 'birth_date'] })
      )
    ).not.toThrow();
  });

  it('accepts a fully configured issuer-scoped-claim deployment', () => {
    expect(() =>
      assertSubjectResolutionProvisioned(
        walletOn({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_BINDING_CLAIMS: ['family_name', 'given_name'],
          OID4VP_SUBJECT_CLAIM: 'personal_administrative_number',
          OID4VP_SUBJECT_CLAIM_ISSUERS: ['https://pid.member-state.example'],
        })
      )
    ).not.toThrow();
  });

  it('is a NO-OP when wallet federation is off, however unconfigured', () => {
    // Deliberately unlike `assertTrustedIssuersUsable` beside it, which is NOT
    // flag-gated. An allowlist typo is a typo whether or not wallet flows are on;
    // "you configured no subject-resolution strategy" is the CORRECT state for a
    // deployment that runs none, and refusing it would make the flag unusable as
    // an off switch.
    expect(() =>
      assertSubjectResolutionProvisioned({ WALLET_FEDERATION_ENABLED: false })
    ).not.toThrow();
  });

  it('yields to the profile gate when the profile itself cannot resolve', () => {
    // `haip-1.0` needs X.509 verifier material nobody has provisioned, so
    // `resolveVerifierProfile` throws. Pre-empting `createConfiguredProviders`
    // here would replace "verifier profile 'haip-1.0' requires …" with a
    // complaint about a subject-resolution variable — neither the operator's
    // first problem nor one they could act on. Proven by the haip integration
    // suite, whose assertion still matches /haip-1.0/.
    expect(() =>
      assertSubjectResolutionProvisioned(walletOn({ OID4VP_VERIFIER_PROFILE: 'haip-1.0' }))
    ).not.toThrow();
  });

  it('yields when no profile is selected at all', () => {
    // `createConfiguredProviders` owns that refusal too ("no VerifierProfile is
    // selected"), and the integration suite asserts its exact wording.
    expect(() =>
      assertSubjectResolutionProvisioned(walletOn({ OID4VP_VERIFIER_PROFILE: '' }))
    ).not.toThrow();
  });
});
