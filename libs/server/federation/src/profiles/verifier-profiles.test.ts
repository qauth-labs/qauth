import { describe, expect, it } from 'vitest';

import { assertSubjectResolutionStrategySelectable } from '../subject/subject-resolution-strategies';
import type { ClientIdPrefix, VerifierProfile, VerifierProfileId } from './verifier-profile.types';
import {
  parseVerifierProfileId,
  VERIFIER_PROFILE_IDS,
  VERIFIER_PROFILES,
} from './verifier-profiles';

/**
 * Every object and array reachable from `value`, as `path → node`.
 *
 * `Object.isFrozen` on the profile alone says nothing about its nested arrays,
 * so the freeze assertion below walks instead of spot-checking: a future profile
 * authored without an inner `Object.freeze(...)` must fail the test rather than
 * pass it by virtue of not being looked at. Paths are carried so a failure names
 * the field.
 */
function collectFreezeTargets(value: unknown, path: string): [string, object][] {
  if (value === null || typeof value !== 'object') return [];

  const children = Array.isArray(value)
    ? value.flatMap((entry, index) => collectFreezeTargets(entry, `${path}[${index}]`))
    : Object.entries(value).flatMap(([key, child]) =>
        collectFreezeTargets(child, `${path}.${key}`)
      );

  return [[path, value], ...children];
}

describe('VERIFIER_PROFILES (issue #299)', () => {
  describe('table invariants — hold for every profile, including future ones', () => {
    it.each(VERIFIER_PROFILE_IDS)("'%s' carries an id matching its table key", (id) => {
      expect(VERIFIER_PROFILES[id].id).toBe(id);
    });

    it.each(VERIFIER_PROFILE_IDS)(
      "'%s' declares clientIdPrefixes equal to its presented prefixes",
      (id) => {
        // #299: "`clientIdPrefixes` (the PERMITTED set) is exactly the set of
        // `presentedPrefixes[].prefix`". A profile permitting a prefix it has no
        // certificate binding for would be a verifier that can name an identity
        // it cannot prove.
        const profile = VERIFIER_PROFILES[id];
        expect([...profile.clientIdPrefixes]).toEqual(
          profile.verifierIdentity.presentedPrefixes.map((b) => b.prefix)
        );
      }
    );

    it.each(VERIFIER_PROFILE_IDS)("'%s' presents at least one prefix", (id) => {
      // A profile with no prefix cannot identify QAuth to a wallet at all.
      expect(VERIFIER_PROFILES[id].verifierIdentity.presentedPrefixes.length).toBeGreaterThan(0);
    });

    it.each(VERIFIER_PROFILE_IDS)("'%s' is frozen against mutation at runtime", (id) => {
      // Profiles are shared, long-lived config. A route mutating one would
      // silently repose every subsequent request.
      expect(Object.isFrozen(VERIFIER_PROFILES[id])).toBe(true);
      expect(() => {
        (VERIFIER_PROFILES[id] as { requestSigning: string }).requestSigning = 'forbidden';
      }).toThrow();
    });

    it.each(VERIFIER_PROFILE_IDS)("'%s' is frozen all the way down, not just at the top", (id) => {
      // The top-level freeze does NOT propagate. A profile that drops the inner
      // `Object.freeze(...)` around a nested array still passes a shallow check
      // while leaving that array mutable — see the next test for the harm.
      const unfrozen = collectFreezeTargets(VERIFIER_PROFILES[id], id)
        .filter(([, node]) => !Object.isFrozen(node))
        .map(([path]) => path);

      expect(unfrozen).toEqual([]);
    });

    it.each(VERIFIER_PROFILE_IDS)("'%s' cannot have its permitted prefix set widened", (id) => {
      // The concrete harm an unfrozen nested array allows: one `push` from any
      // request handler permanently widens the PERMITTED set process-wide, so
      // `haip-1.0` would start accepting `redirect_uri` — unsigned, unverifiable
      // requests under the profile that exists to forbid exactly that.
      //
      // Read through the declared interface, not the `satisfies` literal type:
      // the point is what a CALLER holding a `VerifierProfile` can do to it.
      const profile: VerifierProfile = VERIFIER_PROFILES[id];

      expect(() => {
        (profile.clientIdPrefixes as ClientIdPrefix[]).push('redirect_uri');
      }).toThrow();
      expect(profile.clientIdPrefixes).toEqual(
        profile.verifierIdentity.presentedPrefixes.map((binding) => binding.prefix)
      );
    });

    it.each(VERIFIER_PROFILE_IDS)("'%s' can satisfy its own requestSigning posture", (id) => {
      // A profile declaring `requestSigning: 'required'` while presenting only
      // `redirect_uri` would be unsatisfiable: OID4VP 1.0 §5.9.3 forbids signing
      // that prefix, so every request would be refused by one guard or the other.
      const profile: VerifierProfile = VERIFIER_PROFILES[id];
      if (profile.requestSigning !== 'required') return;

      expect(profile.clientIdPrefixes.filter((prefix) => prefix !== 'redirect_uri')).not.toEqual(
        []
      );
    });

    it.each(VERIFIER_PROFILE_IDS)(
      "'%s' defaults to a subject-resolution strategy a deployment may actually select",
      (id) => {
        // #300/ADR-009: the profile supplies the fail-closed default. A profile
        // defaulting to `key-thumbprint` or `rp-pseudonym` would make every
        // deployment on it unbootable, and one defaulting to `session-binding`
        // would give it a login flow that only authenticates users who are
        // already authenticated. Asserted here rather than only in the resolver,
        // because this is the table where such a value would be introduced.
        expect(() =>
          assertSubjectResolutionStrategySelectable(VERIFIER_PROFILES[id].defaultSubjectResolution)
        ).not.toThrow();
      }
    );

    it('is itself frozen, so a profile cannot be added or replaced at runtime', () => {
      expect(Object.isFrozen(VERIFIER_PROFILES)).toBe(true);
    });

    it('derives VERIFIER_PROFILE_IDS from the table rather than restating it', () => {
      expect([...VERIFIER_PROFILE_IDS].sort()).toEqual(Object.keys(VERIFIER_PROFILES).sort());
    });
  });

  describe("'oid4vp-1.0-base' — the protocol floor that ships first (#296 Q1)", () => {
    const base = VERIFIER_PROFILES['oid4vp-1.0-base'];

    it('prefers the certificate-free redirect_uri prefix, so it runs on today’s crypto', () => {
      expect(base.verifierIdentity.presentedPrefixes[0]).toEqual({ prefix: 'redirect_uri' });
    });

    it('uses plain direct_post and forbids response encryption', () => {
      // `direct_post.jwt` needs the JWE stack from #298 and is HAIP's requirement,
      // not the protocol floor's.
      expect([...base.responseModes]).toEqual(['direct_post']);
      expect(base.responseEncryption).toBe('forbidden');
    });

    it('does not mandate credential status checking', () => {
      // Token Status List (#297) is a HAIP §6.1 mandate.
      expect(base.requireCredentialStatus).toBe(false);
    });

    it('contains no HAIP-only constant (the leak this table exists to prevent)', () => {
      // #299 AC: "No HAIP-specific constant appears outside the `haip-1.0`
      // profile definition." Asserted structurally on the profile most at risk
      // of acquiring one by copy-paste.
      const serialized = JSON.stringify(base);
      expect(serialized).not.toContain('x509_hash');
      expect(serialized).not.toContain('direct_post.jwt');
      expect(serialized).not.toContain('mso_mdoc');
    });
  });

  describe("'haip-1.0' — the EUDI-aligned profile, gated on #298", () => {
    const haip = VERIFIER_PROFILES['haip-1.0'];

    it('presents only x509_hash, backed by a non-self-signed chain (WRPAC)', () => {
      expect([...haip.clientIdPrefixes]).toEqual(['x509_hash']);
      expect(haip.verifierIdentity.presentedPrefixes[0]).toEqual({
        prefix: 'x509_hash',
        requires: 'non-self-signed-chain',
      });
    });

    it('requires signing, encrypted responses and ES256 (HAIP §5.1, §7)', () => {
      expect(haip.requestSigning).toBe('required');
      expect(haip.responseEncryption).toBe('required');
      expect([...haip.responseModes]).toEqual(['direct_post.jwt']);
      expect([...haip.signingAlgs]).toEqual(['ES256']);
    });

    it('excludes EdDSA — QAuth’s current algorithm does not satisfy the profile', () => {
      // HAIP §7 mandates ES256 at minimum and EdDSA is not in its mandatory set.
      // This is why the profile cannot be honoured until #298 lands.
      expect(haip.signingAlgs).not.toContain('EdDSA');
    });

    it('mandates credential status checking (HAIP §6.1, #297)', () => {
      expect(haip.requireCredentialStatus).toBe(true);
    });

    it('resolves issuer keys only via x5c', () => {
      expect([...haip.issuerKeyResolution]).toEqual(['x5c']);
    });
  });

  describe('parseVerifierProfileId — fail-CLOSED, unlike ADR-008’s parseEnvironment', () => {
    it.each(VERIFIER_PROFILE_IDS)("accepts the known id '%s'", (id) => {
      expect(parseVerifierProfileId(id)).toBe(id);
    });

    it.each([null, undefined, '', 'HAIP-1.0', 'haip', 'oid4vp', 'haip-1.1', 'production'])(
      'discards %o rather than coercing it to a default',
      (raw) => {
        // There is no safe default to fall back to: `haip-1.0` is not a stricter
        // `oid4vp-1.0-base`, it is a different ecosystem. #296 LOCKED: "There is
        // never a permissive fallback to the more capable profile."
        expect(parseVerifierProfileId(raw)).toBeUndefined();
      }
    );

    it('is case-sensitive, so a near-miss fails closed instead of nearly working', () => {
      expect(parseVerifierProfileId('OID4VP-1.0-BASE' as VerifierProfileId)).toBeUndefined();
    });
  });
});
