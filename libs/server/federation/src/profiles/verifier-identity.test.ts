import { describe, expect, it } from 'vitest';

import {
  assertPrefixProvisioned,
  assertRequestSigningAllowed,
  assertRequestSigningPosture,
  assertVerifierIdentityProvisioned,
  NO_VERIFIER_MATERIAL,
  type ProvisionedVerifierMaterial,
} from './verifier-identity';
import type { VerifierProfile } from './verifier-profile.types';
import { VERIFIER_PROFILE_IDS, VERIFIER_PROFILES } from './verifier-profiles';

const base = VERIFIER_PROFILES['oid4vp-1.0-base'];
const haip = VERIFIER_PROFILES['haip-1.0'];

/** The leaf certificate `x509_san_dns` needs; arrives with #298 (ES256). */
const LEAF_CERT: ProvisionedVerifierMaterial = { available: ['leaf-cert'] };

/** The non-self-signed WRPAC chain `x509_hash` needs (#296 Q4). */
const WRPAC: ProvisionedVerifierMaterial = { available: ['non-self-signed-chain'] };

/**
 * The message a guard refused with. Asserting on message CONTENT (not just that
 * something threw) is what makes the "advice must be derived from the profile"
 * tests below able to fail; `toThrow(/re/)` alone cannot prove the absence of a
 * wrong suggestion.
 */
function messageOf(run: () => void): string {
  try {
    run();
  } catch (error) {
    return (error as Error).message;
  }

  throw new Error('expected the guard to refuse, but it returned normally');
}

describe('assertVerifierIdentityProvisioned (issue #299)', () => {
  describe('the shipped profiles, with nothing provisioned (today’s state)', () => {
    it('lets oid4vp-1.0-base start — its preferred redirect_uri prefix needs no certificate', () => {
      expect(() => assertVerifierIdentityProvisioned(base, NO_VERIFIER_MATERIAL)).not.toThrow();
    });

    it('refuses haip-1.0 — the WRPAC chain it presents is not provisioned', () => {
      // The #299 fail-closed AC. Selecting HAIP without the certificate material
      // must refuse rather than silently downgrade to a weaker prefix or profile.
      expect(() => assertVerifierIdentityProvisioned(haip, NO_VERIFIER_MATERIAL)).toThrow(
        /non-self-signed-chain/
      );
    });

    it('defaults to "nothing provisioned" when the argument is omitted', () => {
      // The default must be the refusing one: a caller that forgets to pass
      // material should fail closed, not sail through.
      expect(() => assertVerifierIdentityProvisioned(haip)).toThrow();
      expect(() => assertVerifierIdentityProvisioned(base)).not.toThrow();
    });

    it('names the issues that unblock the refusal, so the operator is not stuck', () => {
      expect(() => assertVerifierIdentityProvisioned(haip)).toThrow(/#298.*#233|#233.*#298/s);
    });
  });

  describe('once material is provisioned (the #298/#233 future)', () => {
    it('accepts haip-1.0 when the non-self-signed chain is available', () => {
      expect(() => assertVerifierIdentityProvisioned(haip, WRPAC)).not.toThrow();
    });

    it('does not accept the wrong material kind', () => {
      // A leaf certificate is not a WRPAC chain; accepting one for the other
      // would be exactly the silent downgrade #299 forbids.
      expect(() => assertVerifierIdentityProvisioned(haip, LEAF_CERT)).toThrow(
        /non-self-signed-chain/
      );
    });
  });

  describe('malformed profile definitions', () => {
    it('refuses a profile that presents no prefix at all', () => {
      // Not reachable from the shipped table; guards a future profile authored
      // with an empty binding list, which would be a verifier with no identity.
      const empty = {
        ...base,
        verifierIdentity: { presentedPrefixes: [] },
      } as unknown as VerifierProfile;

      expect(() => assertVerifierIdentityProvisioned(empty)).toThrow(
        /presents no Client Identifier Prefix/
      );
    });
  });

  it('checks only the PREFERRED prefix, which is why it is a floor and not the whole story', () => {
    // `oid4vp-1.0-base` starts with nothing provisioned because its preferred
    // prefix is certificate-free — while still PERMITTING `x509_san_dns`, whose
    // leaf certificate does not exist. Boot-time is therefore the wrong place to
    // ask "may this prefix be used"; `assertPrefixProvisioned` is.
    expect(() => assertVerifierIdentityProvisioned(base, NO_VERIFIER_MATERIAL)).not.toThrow();
    expect(base.clientIdPrefixes).toContain('x509_san_dns');
    expect(() => assertPrefixProvisioned(base, 'x509_san_dns', NO_VERIFIER_MATERIAL)).toThrow(
      /leaf-cert/
    );
  });
});

describe('assertPrefixProvisioned (issue #299)', () => {
  it('permits redirect_uri with nothing provisioned — it needs no certificate', () => {
    expect(() => assertPrefixProvisioned(base, 'redirect_uri', NO_VERIFIER_MATERIAL)).not.toThrow();
  });

  it('accepts x509_san_dns once its leaf certificate is provisioned', () => {
    expect(() => assertPrefixProvisioned(base, 'x509_san_dns', LEAF_CERT)).not.toThrow();
  });

  it('refuses x509_san_dns when only a WRPAC chain is provisioned', () => {
    // Material kinds are not interchangeable: a chain issued for `x509_hash` is
    // not the origin-matching leaf `x509_san_dns` puts in its `x5c` header.
    expect(() => assertPrefixProvisioned(base, 'x509_san_dns', WRPAC)).toThrow(/leaf-cert/);
  });

  it('defaults to "nothing provisioned" when the argument is omitted', () => {
    // Same fail-closed default as the boot-time check: an unthreaded caller must
    // be refused, not trusted.
    expect(() => assertPrefixProvisioned(base, 'x509_san_dns')).toThrow(/leaf-cert/);
  });

  it('refuses a prefix the profile declares no binding for', () => {
    // A prefix with no binding is a verifier identity QAuth cannot prove. Not
    // reachable from the shipped table — `clientIdPrefixes` and
    // `presentedPrefixes` are asserted equal — so this guards future drift.
    expect(() => assertPrefixProvisioned(base, 'x509_hash', WRPAC)).toThrow(
      /declares no certificate binding/
    );
  });
});

describe('assertRequestSigningPosture (issue #299)', () => {
  const forbidding: VerifierProfile = { ...base, requestSigning: 'forbidden' };

  it.each<[string, VerifierProfile, boolean]>([
    ["'required' accepts a signed request", haip, true],
    ["'permitted' accepts a signed request", base, true],
    ["'permitted' accepts an unsigned request", base, false],
    ["'forbidden' accepts an unsigned request", forbidding, false],
  ])('%s', (_label, profile, signed) => {
    expect(() => assertRequestSigningPosture(profile, { signed })).not.toThrow();
  });

  it('refuses an unsigned request under a profile that requires signing', () => {
    // `CapabilityPosture` is a triple and only `forbidden` was ever enforced, so
    // `haip-1.0`'s `requestSigning: 'required'` (HAIP §5.1) was decorative: an
    // unsigned request went out under the EUDI-aligned profile looking compliant.
    expect(() => assertRequestSigningPosture(haip, { signed: false })).toThrow(
      /requires signed Authorization Requests/
    );
  });

  it('refuses a signed request under a profile that forbids signing', () => {
    expect(() => assertRequestSigningPosture(forbidding, { signed: true })).toThrow(
      /forbids request signing/
    );
  });

  it('is the single place the posture is written down, not a second copy', () => {
    // `assertRequestSigningAllowed` implies `signed: true` and delegates here. If
    // the two ever drift, one call path permits what the other refuses.
    expect(() => assertRequestSigningAllowed(forbidding, 'x509_san_dns', LEAF_CERT)).toThrow(
      /forbids request signing/
    );
  });
});

describe('assertRequestSigningAllowed (issue #299)', () => {
  it('refuses to sign a redirect_uri request (OID4VP 1.0 §5.9.3)', () => {
    // The concrete example #299 gives: such a request is unverifiable, so a
    // signature over it proves nothing.
    expect(() => assertRequestSigningAllowed(base, 'redirect_uri')).toThrow(/5\.9\.3/);
  });

  it('applies the §5.9.3 prohibition before the profile’s own prefix set', () => {
    // `haip-1.0` does NOT present `redirect_uri`, so a prefix-set check running
    // first reports "does not present the 'redirect_uri' prefix" and hides the
    // protocol prohibition entirely. That wording invites a #233 implementer to
    // "fix" it by widening haip-1.0's `clientIdPrefixes` — the exact HAIP
    // violation this table exists to prevent.
    expect(() => assertRequestSigningAllowed(haip, 'redirect_uri', WRPAC)).toThrow(/5\.9\.3/);
  });

  it('applies the §5.9.3 prohibition before the profile’s signing posture', () => {
    // The prohibition is protocol-level and holds regardless of configuration,
    // so a profile that "requires" signing must still be refused for this prefix
    // rather than being allowed to override the spec.
    const requiresSigning: VerifierProfile = { ...base, requestSigning: 'required' };

    expect(() => assertRequestSigningAllowed(requiresSigning, 'redirect_uri')).toThrow(/5\.9\.3/);
  });

  it('suggests only prefixes the ACTIVE profile actually presents', () => {
    // #299 AC: no HAIP-specific constant outside the `haip-1.0` definition. A
    // hardcoded "present 'x509_san_dns' or 'x509_hash'" is wrong under both
    // profiles — base does not present `x509_hash`, HAIP does not present
    // `x509_san_dns` — and pointing an operator at a prefix their profile cannot
    // use is an invitation to widen the profile until the advice becomes true.
    const underBase = messageOf(() => assertRequestSigningAllowed(base, 'redirect_uri'));
    const underHaip = messageOf(() => assertRequestSigningAllowed(haip, 'redirect_uri', WRPAC));

    expect(underBase).toContain("'x509_san_dns'");
    expect(underBase).not.toContain('x509_hash');

    expect(underHaip).toContain("'x509_hash'");
    expect(underHaip).not.toContain('x509_san_dns');
  });

  it('says so plainly when the profile can sign nothing at all', () => {
    // A profile presenting only `redirect_uri` has no signable prefix, and the
    // refusal must not end with an empty "Present  to sign" dangling at the
    // operator.
    const redirectOnly: VerifierProfile = {
      ...base,
      clientIdPrefixes: ['redirect_uri'],
      verifierIdentity: { presentedPrefixes: [{ prefix: 'redirect_uri' }] },
    };

    expect(messageOf(() => assertRequestSigningAllowed(redirectOnly, 'redirect_uri'))).toContain(
      'cannot sign any request'
    );
  });

  it('permits signing x509_san_dns under the base profile once its certificate exists', () => {
    expect(() => assertRequestSigningAllowed(base, 'x509_san_dns', LEAF_CERT)).not.toThrow();
  });

  it('refuses to sign x509_san_dns on a base deployment with no certificate at all', () => {
    // The reachable gap: boot succeeds because the PREFERRED prefix is
    // certificate-free, and the profile still PERMITS `x509_san_dns`. Allowing
    // this call would build an `x5c` header out of a leaf certificate nobody
    // provisioned — a verifier identity QAuth names but cannot prove (#299).
    expect(() => assertVerifierIdentityProvisioned(base, NO_VERIFIER_MATERIAL)).not.toThrow();
    expect(() => assertRequestSigningAllowed(base, 'x509_san_dns', NO_VERIFIER_MATERIAL)).toThrow(
      /leaf-cert/
    );
  });

  it('defaults to "nothing provisioned", so an unthreaded caller cannot sign', () => {
    expect(() => assertRequestSigningAllowed(base, 'x509_san_dns')).toThrow(/leaf-cert/);
  });

  it('permits signing x509_hash under haip-1.0 once the WRPAC chain exists', () => {
    expect(() => assertRequestSigningAllowed(haip, 'x509_hash', WRPAC)).not.toThrow();
  });

  it('refuses to sign x509_hash under haip-1.0 before the WRPAC chain is provisioned', () => {
    expect(() => assertRequestSigningAllowed(haip, 'x509_hash', NO_VERIFIER_MATERIAL)).toThrow(
      /non-self-signed-chain/
    );
  });

  it('refuses a prefix the profile does not present', () => {
    // haip-1.0 presents only x509_hash; asking it to sign an x509_san_dns request
    // is a caller bug, and must not silently succeed because signing is required.
    expect(() => assertRequestSigningAllowed(haip, 'x509_san_dns', WRPAC)).toThrow(
      /does not present the 'x509_san_dns'/
    );
  });

  it('refuses when the profile forbids signing outright', () => {
    const noSigning: VerifierProfile = { ...base, requestSigning: 'forbidden' };
    expect(() => assertRequestSigningAllowed(noSigning, 'x509_san_dns', LEAF_CERT)).toThrow(
      /forbids request signing/
    );
  });
});

/**
 * Key names that read as ISSUER-direction configuration. #236 decides whether a
 * credential's ISSUER is trusted; a `VerifierProfile` decides how QAuth proves it
 * is the VERIFIER. A key like `trustedIssuers` or `trustAnchors` appearing in
 * this table would mean the two opposite trust directions had been conflated,
 * letting "we trust this issuer" answer "who are we?".
 */
const ISSUER_DIRECTION_KEY = /issuer|trust|anchor|allowlist|revocation/i;

/**
 * The single acknowledged exception, by FULL path.
 *
 * `issuerKeyResolution` is issuer-KEY-RESOLUTION mechanics — where a credential's
 * signing key is located (`x5c` header vs issuer metadata) — not a decision about
 * whether that issuer is trusted, which is #236's and appears nowhere here.
 * Matching the full path rather than the bare key means the same name reappearing
 * nested somewhere else still fails.
 */
const ACKNOWLEDGED_ISSUER_PATHS: readonly string[] = ['issuerKeyResolution'];

/** Paths of every issuer-direction key reachable from `value`. */
function findIssuerDirectionKeys(value: unknown, path = ''): string[] {
  if (value === null || typeof value !== 'object') return [];

  if (Array.isArray(value)) {
    return value.flatMap((entry, index) => findIssuerDirectionKeys(entry, `${path}[${index}]`));
  }

  return Object.entries(value).flatMap(([key, child]) => {
    const here = path === '' ? key : `${path}.${key}`;
    if (ACKNOWLEDGED_ISSUER_PATHS.includes(here)) return [];

    return [
      ...(ISSUER_DIRECTION_KEY.test(key) ? [here] : []),
      ...findIssuerDirectionKeys(child, here),
    ];
  });
}

describe('the VERIFIER trust direction is not issuer trust (#236)', () => {
  it.each(VERIFIER_PROFILE_IDS)("'%s' carries no issuer-direction field", (id) => {
    // #299 AC: the two directions must share no code path. The scan covers the
    // WHOLE profile — `issuerKeyResolution` lives at profile level, so scanning
    // only `verifierIdentity` would exclude the one place issuers are mentioned
    // and could never catch a sibling field like `trustedIssuers`.
    expect(findIssuerDirectionKeys(VERIFIER_PROFILES[id])).toEqual([]);
  });

  it('detects an issuer-trust field added at profile level', () => {
    // Positive control. Without it this test is tautological: it would assert
    // the shipped table against itself and pass for a scan that can never match.
    const conflated = { ...base, trustedIssuers: ['did:example:issuer'] };

    expect(findIssuerDirectionKeys(conflated)).toEqual(['trustedIssuers']);
  });

  it('detects an issuer-trust field nested inside verifierIdentity', () => {
    const conflated = {
      ...base,
      verifierIdentity: { ...base.verifierIdentity, trustAnchors: [] },
    };

    expect(findIssuerDirectionKeys(conflated)).toEqual(['verifierIdentity.trustAnchors']);
  });

  it('does not flag issuerKeyResolution, the one acknowledged mention of issuers', () => {
    // Key LOCATION, not issuer TRUST — the distinction the exception encodes.
    expect(base.issuerKeyResolution).toContain('issuer-metadata');
    expect(findIssuerDirectionKeys(base)).toEqual([]);
  });
});
