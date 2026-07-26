import { describe, expect, it } from 'vitest';

import { resolveVerifierProfile } from './resolve-verifier-profile';
import { NO_VERIFIER_MATERIAL, type ProvisionedVerifierMaterial } from './verifier-identity';
import { VERIFIER_PROFILES } from './verifier-profiles';

/** The non-self-signed WRPAC chain `haip-1.0` cannot start without (#296 Q4). */
const WRPAC: ProvisionedVerifierMaterial = { available: ['non-self-signed-chain'] };

describe('resolveVerifierProfile (issue #299)', () => {
  describe('fail-closed: no selection means refuse, never a default', () => {
    it.each([
      ['both absent', null, null],
      ['empty realm and env', {}, {}],
      ['env present but unset', {}, { OID4VP_VERIFIER_PROFILE: undefined }],
      ['null values on both sides', { verifierProfile: null }, { OID4VP_VERIFIER_PROFILE: null }],
    ])('returns undefined when %s', (_label, realm, env) => {
      expect(resolveVerifierProfile(realm, env)).toBeUndefined();
    });

    it('discards an unrecognised env value instead of downgrading to a working profile', () => {
      // The dangerous failure is a typo silently selecting the permissive
      // profile. #296 LOCKED: a deployment that selects no valid profile refuses
      // wallet flows.
      expect(
        resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0' })
      ).toBeUndefined();
    });

    it('discards an unrecognised realm value even when it looks close', () => {
      expect(resolveVerifierProfile({ verifierProfile: 'haip' }, null)).toBeUndefined();
    });
  });

  describe('resolution order — realm selection is all-or-nothing', () => {
    it('consults env only when the realm expressed no opinion', () => {
      expect(resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' })).toBe(
        VERIFIER_PROFILES['oid4vp-1.0-base']
      );
    });

    it.each([
      ['undefined', undefined],
      ['null', null],
    ])('treats a %s realm value as absent and falls through to env', (_label, verifierProfile) => {
      // The genuinely-absent case: no `realms.verifier_profile` row value means
      // the realm inherits the deployment-wide default, which is the whole point
      // of having one.
      expect(
        resolveVerifierProfile({ verifierProfile }, { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' })
      ).toBe(VERIFIER_PROFILES['oid4vp-1.0-base']);
    });

    it('lets the realm override the deployment-wide default', () => {
      // No realms column exists yet, so this proves the seam rather than a
      // shipped behaviour: adding `realms.verifier_profile` later needs no
      // change here or at any call site.
      expect(
        resolveVerifierProfile(
          { verifierProfile: 'haip-1.0' },
          { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' },
          WRPAC
        )
      ).toBe(VERIFIER_PROFILES['haip-1.0']);
    });

    it('refuses an unparseable realm value rather than falling through to env', () => {
      // A realm row MEANT to run haip-1.0 with a typo'd value must not quietly
      // run the deployment default instead: that is unencrypted `direct_post`
      // and revoked credentials accepted, under a realm that asked for neither.
      // ADR-008's resolver can compose two values because `production` is a safe
      // default; there is no safe default here (#296 LOCKED), so an expressed
      // opinion that does not parse is refused outright.
      expect(
        resolveVerifierProfile(
          { verifierProfile: 'nonsense' },
          { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' }
        )
      ).toBeUndefined();
    });

    it('refuses an empty realm value rather than treating it as absent', () => {
      // No trimming, no coercion: normalising a bad column value into "unset" is
      // how a downgrade becomes silent.
      expect(
        resolveVerifierProfile(
          { verifierProfile: '' },
          { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' }
        )
      ).toBeUndefined();
    });
  });

  describe('a resolved profile is always a provisioned one (#299)', () => {
    it('throws when the selected env profile lacks its X.509 material', () => {
      // Every deployment selecting haip-1.0 today: the WRPAC arrives with
      // #298/#233. Refusing here rather than at first wallet request is what
      // makes the gap a boot failure instead of a runtime surprise.
      expect(() => resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'haip-1.0' })).toThrow(
        /non-self-signed-chain/
      );
    });

    it('throws when a REALM-selected profile lacks its X.509 material', () => {
      // The gap the fold-in closes: the provisioning assertion used to run once
      // at bootstrap against the env-level profile, so a realm row resolving
      // haip-1.0 would hand back a profile whose material was never asserted.
      expect(() =>
        resolveVerifierProfile(
          { verifierProfile: 'haip-1.0' },
          { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' }
        )
      ).toThrow(/non-self-signed-chain/);
    });

    it('defaults to "nothing provisioned", so a caller that omits material fails closed', () => {
      expect(() => resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'haip-1.0' })).toThrow();
      expect(resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'haip-1.0' }, WRPAC)).toBe(
        VERIFIER_PROFILES['haip-1.0']
      );
    });

    it('keeps "nothing selected" and "selected but half-configured" distinguishable', () => {
      // Both refuse, but the operator fix differs — set the env var vs provision
      // a certificate — so collapsing them into a single `undefined` would strip
      // the only signal that tells the two apart.
      expect(resolveVerifierProfile(null, {}, NO_VERIFIER_MATERIAL)).toBeUndefined();
      expect(() =>
        resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'haip-1.0' }, NO_VERIFIER_MATERIAL)
      ).toThrow();
    });
  });

  describe('#299 AC — switching the configured profile changes the resolved posture', () => {
    it('yields a materially different posture for each profile', () => {
      const base = resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'oid4vp-1.0-base' });
      const haip = resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'haip-1.0' }, WRPAC);

      expect(base?.responseEncryption).toBe('forbidden');
      expect(haip?.responseEncryption).toBe('required');
      expect(base?.clientIdPrefixes).not.toEqual(haip?.clientIdPrefixes);
      expect(base?.requireCredentialStatus).not.toBe(haip?.requireCredentialStatus);
    });
  });

  it('returns the shared frozen table entry, not a copy', () => {
    // Identity matters: callers compare and cache profiles, and a per-call clone
    // would defeat the freeze that keeps posture stable across a request.
    const resolved = resolveVerifierProfile(null, { OID4VP_VERIFIER_PROFILE: 'haip-1.0' }, WRPAC);
    expect(resolved).toBe(VERIFIER_PROFILES['haip-1.0']);
  });
});
