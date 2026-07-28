import { describe, expect, it } from 'vitest';

import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import {
  assertCredentialStatusProvisioned,
  NO_CREDENTIAL_STATUS_PROVISIONING,
} from './credential-status-provisioning';

const BOTH = { trustAnchors: true, uriAllowlist: true } as const;

describe('assertCredentialStatusProvisioned — the boot gate (#297/#378)', () => {
  it('refuses haip-1.0 when nothing is provisioned', () => {
    expect(() => assertCredentialStatusProvisioned(VERIFIER_PROFILES['haip-1.0'])).toThrow(
      /requires credential revocation checking/
    );
  });

  it('defaults to the refusing answer, so a caller that forgets to thread it fails closed', () => {
    expect(NO_CREDENTIAL_STATUS_PROVISIONING).toEqual({
      trustAnchors: false,
      uriAllowlist: false,
    });
    expect(() => assertCredentialStatusProvisioned(VERIFIER_PROFILES['haip-1.0'])).toThrow();
  });

  it('names the anchors when only the allowlist is provisioned', () => {
    // The refusal has to say WHICH half is missing: no anchors and no allowlist
    // are different mistakes with different fixes, and an operator who set one
    // needs to be told about the other rather than re-reading both docs.
    expect(() =>
      assertCredentialStatusProvisioned(VERIFIER_PROFILES['haip-1.0'], {
        trustAnchors: false,
        uriAllowlist: true,
      })
    ).toThrow(/OID4VP_STATUS_LIST_TRUST_ANCHORS/);
  });

  it('names the allowlist when only the anchors are provisioned', () => {
    expect(() =>
      assertCredentialStatusProvisioned(VERIFIER_PROFILES['haip-1.0'], {
        trustAnchors: true,
        uriAllowlist: false,
      })
    ).toThrow(/OID4VP_STATUS_LIST_URI_ALLOWLIST/);
  });

  it('names both when neither is provisioned', () => {
    let message = '';
    try {
      assertCredentialStatusProvisioned(VERIFIER_PROFILES['haip-1.0']);
    } catch (error) {
      message = error instanceof Error ? error.message : String(error);
    }

    expect(message).toContain('OID4VP_STATUS_LIST_TRUST_ANCHORS');
    expect(message).toContain('OID4VP_STATUS_LIST_URI_ALLOWLIST');
  });

  it('accepts haip-1.0 once both halves exist', () => {
    expect(() =>
      assertCredentialStatusProvisioned(VERIFIER_PROFILES['haip-1.0'], BOTH)
    ).not.toThrow();
  });

  it('never refuses a profile that does not require credential status', () => {
    // `oid4vp-1.0-base` declares `requireCredentialStatus: false` — base
    // OID4VP 1.0 mandates no revocation mechanism, so the unprovisioned default
    // must not refuse it.
    expect(() =>
      assertCredentialStatusProvisioned(VERIFIER_PROFILES['oid4vp-1.0-base'])
    ).not.toThrow();
  });

  it('names no profile in its own logic, so a future profile is gated for free', () => {
    // Profiles are DATA (#299 AC). The gate reads the declared capability.
    const hypothetical = {
      ...VERIFIER_PROFILES['oid4vp-1.0-base'],
      id: 'oid4vp-1.0-base' as const,
      requireCredentialStatus: true,
    };

    expect(() => assertCredentialStatusProvisioned(hypothetical)).toThrow(
      /requires credential revocation checking/
    );
  });
});
