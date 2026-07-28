import { describe, expect, it, vi } from 'vitest';

import { NO_KEY_STORAGE_ASSURANCE } from '../attestation/key-storage-assurance';
import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { ValidatedIssuer } from '../trust/issuer-identity';
import {
  type AssurancePolicy,
  createIssuerAssurancePolicy,
  LOW_ONLY_ASSURANCE_POLICY,
  resolveCredentialAssurance,
} from './credential-assurance';

const TEST_VCT = 'https://credentials.example.com/pid';

/**
 * A minimal {@link ValidatedCredential}. The issuer is a REAL
 * {@link ValidatedIssuer} — the whole point of this module is that an issuer
 * identity which never went through key resolution is worth nothing, so a
 * hand-built stand-in would test the opposite of what matters.
 */
function credential(
  identifier: string,
  credentialType: string = TEST_VCT,
  keyResolution: 'x5c' | 'issuer-metadata' = 'issuer-metadata'
): ValidatedCredential {
  return {
    queryId: 'pid',
    format: 'dc+sd-jwt',
    credentialType,
    issuer: ValidatedIssuer.fromValidatedPresentation({ identifier, keyResolution }),
    claims: Object.freeze({}),
    validity: {},
    assurance: {
      credentialType,
      issuerKeyResolution: keyResolution,
      issuerSignatureAlgorithm: 'ES256',
      keyBindingAlgorithm: 'ES256',
      disclosedClaimCount: 1,
      statusChecked: 'not-required',
      // #308's evidence, and `'none'` is the honest value for this fixture: no
      // key attestation was validated. Assurance policy must NOT read it — the
      // two are independent inputs (see `AssuredKeyStorage`).
      keyStorageAssurance: NO_KEY_STORAGE_ASSURANCE,
    },
  };
}

describe('createIssuerAssurancePolicy (ADR-004 — assurance is a property of the issuer)', () => {
  it('grants the configured level to a listed issuer', () => {
    const policy = createIssuerAssurancePolicy([
      { issuer: 'https://issuer.example', assuranceLevel: 'high' },
    ]);

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('high');
  });

  it('assures nothing for an issuer that is not listed', () => {
    const policy = createIssuerAssurancePolicy([
      { issuer: 'https://issuer.example', assuranceLevel: 'high' },
    ]);

    expect(policy.levelFor(credential('https://other.example'))).toBe('low');
  });

  it('assures nothing when the policy is empty — fail-closed, never assure-all', () => {
    expect(createIssuerAssurancePolicy([]).levelFor(credential('https://issuer.example'))).toBe(
      'low'
    );
  });

  it('matches through canonicalization on BOTH sides', () => {
    const policy = createIssuerAssurancePolicy([
      { issuer: 'https://Issuer.EXAMPLE:443/', assuranceLevel: 'substantial' },
    ]);

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('substantial');
  });

  it('does not treat a sub-path or a look-alike host as the assured issuer', () => {
    const policy = createIssuerAssurancePolicy([
      { issuer: 'https://issuer.example', assuranceLevel: 'high' },
    ]);

    expect(policy.levelFor(credential('https://issuer.example/evil'))).toBe('low');
    expect(policy.levelFor(credential('https://issuer.example.evil.test'))).toBe('low');
  });

  it('refuses an issuer identity that was never validated, however it was cast', () => {
    // The bypass this module must not have: a raw `iss` string off the wire,
    // wearing a `ValidatedIssuer` type through a cast. `#validated in value`
    // survives the cast; `instanceof` would not have.
    const policy = createIssuerAssurancePolicy([
      { issuer: 'https://issuer.example', assuranceLevel: 'high' },
    ]);
    const forged = {
      ...credential('https://issuer.example'),
      issuer: {
        identifier: 'https://issuer.example',
        keyResolution: 'issuer-metadata',
      } as unknown as ValidatedIssuer,
    };

    expect(policy.levelFor(forged)).toBe('low');
  });

  it('restricts a type-scoped entry to the credential types it names', () => {
    const policy = createIssuerAssurancePolicy([
      {
        issuer: 'https://issuer.example',
        assuranceLevel: 'high',
        credentialTypes: [TEST_VCT],
      },
    ]);

    expect(policy.levelFor(credential('https://issuer.example', TEST_VCT))).toBe('high');
    expect(
      policy.levelFor(
        credential('https://issuer.example', 'https://credentials.example.com/loyalty')
      )
    ).toBe('low');
  });

  it('prefers the more specific type-scoped entry over the issuer-wide one', () => {
    // "this issuer is substantial, except its PID which is high" — the shape an
    // operator needs when one issuer runs two identity-proofing processes.
    const policy = createIssuerAssurancePolicy([
      { issuer: 'https://issuer.example', assuranceLevel: 'substantial' },
      { issuer: 'https://issuer.example', assuranceLevel: 'high', credentialTypes: [TEST_VCT] },
    ]);

    expect(policy.levelFor(credential('https://issuer.example', TEST_VCT))).toBe('high');
    expect(policy.levelFor(credential('https://issuer.example', 'urn:other'))).toBe('substantial');
  });

  it.each([
    ['a malformed issuer identifier', { issuer: 'not-a-url', assuranceLevel: 'high' }],
    ['an http issuer identifier', { issuer: 'http://issuer.example', assuranceLevel: 'high' }],
    ['a level of low', { issuer: 'https://issuer.example', assuranceLevel: 'low' }],
    ['an unknown level', { issuer: 'https://issuer.example', assuranceLevel: 'HIGH' }],
    ['a null entry', null],
  ] as const)('drops %s rather than granting anything', (_label, entry) => {
    const policy = createIssuerAssurancePolicy([
      entry as unknown as { issuer: string; assuranceLevel: 'high' },
    ]);

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('low');
  });

  describe('key-attestation seam (HAIP §9.2, #308)', () => {
    it('refuses an entry that requires hardware storage while nothing proves it', () => {
      // Until #308 lands there is no key attestation, so `keyStorage` is never
      // populated and such an entry can never grant. Fail-closed by
      // construction: an eIDAS `high` claim that assumed a secure
      // cryptographic device nobody verified is the unearned assertion this
      // module exists to prevent.
      const policy = createIssuerAssurancePolicy([
        {
          issuer: 'https://issuer.example',
          assuranceLevel: 'high',
          requiresKeyStorage: 'hardware',
        },
      ]);

      expect(policy.levelFor(credential('https://issuer.example'))).toBe('low');
      expect(policy.levelFor(credential('https://issuer.example'), {})).toBe('low');
      expect(
        policy.levelFor(credential('https://issuer.example'), { keyStorage: 'software' })
      ).toBe('low');
    });

    it('grants once #308 supplies the proof the entry demands', () => {
      const policy = createIssuerAssurancePolicy([
        {
          issuer: 'https://issuer.example',
          assuranceLevel: 'high',
          requiresKeyStorage: 'hardware',
        },
      ]);

      expect(
        policy.levelFor(credential('https://issuer.example'), { keyStorage: 'hardware' })
      ).toBe('high');
    });

    it('ignores key-storage evidence an entry did not ask for', () => {
      const policy = createIssuerAssurancePolicy([
        { issuer: 'https://issuer.example', assuranceLevel: 'substantial' },
      ]);

      expect(
        policy.levelFor(credential('https://issuer.example'), { keyStorage: 'software' })
      ).toBe('substantial');
    });
  });
});

describe('LOW_ONLY_ASSURANCE_POLICY (#237)', () => {
  it('assures nothing, for any credential', () => {
    expect(LOW_ONLY_ASSURANCE_POLICY.levelFor(credential('https://issuer.example'))).toBe('low');
  });
});

describe('resolveCredentialAssurance (#237)', () => {
  it('assures nothing when no policy could be resolved', () => {
    expect(resolveCredentialAssurance(null, credential('https://issuer.example'))).toBe('low');
    expect(resolveCredentialAssurance(undefined, credential('https://issuer.example'))).toBe('low');
  });

  it('returns the level the policy established', () => {
    const policy = createIssuerAssurancePolicy([
      { issuer: 'https://issuer.example', assuranceLevel: 'substantial' },
    ]);

    expect(resolveCredentialAssurance(policy, credential('https://issuer.example'))).toBe(
      'substantial'
    );
  });

  it('contains a policy that throws, reports it, and degrades to low', () => {
    // A throw must cost the deployment its `acr` claim, never the login: that
    // is the only containment direction that neither grants unearned assurance
    // nor refuses a legitimate sign-in.
    const onPolicyError = vi.fn();
    const broken: AssurancePolicy = {
      levelFor: () => {
        throw new Error('policy backend exploded');
      },
    };

    expect(
      resolveCredentialAssurance(broken, credential('https://issuer.example'), undefined, {
        onPolicyError,
      })
    ).toBe('low');
    expect(onPolicyError).toHaveBeenCalledTimes(1);
  });

  it('does not let a throwing reporter become the fault', () => {
    const broken: AssurancePolicy = {
      levelFor: () => {
        throw new Error('policy backend exploded');
      },
    };

    expect(
      resolveCredentialAssurance(broken, credential('https://issuer.example'), undefined, {
        onPolicyError: () => {
          throw new Error('logger exploded too');
        },
      })
    ).toBe('low');
  });

  it.each([
    ['a truthy non-level', 'HIGH'],
    ['a boolean', true],
    ['an object', { level: 'high' }],
    ['undefined', undefined],
  ] as const)(
    'reads %s returned by a third-party policy as low, not as a grant',
    (_label, value) => {
      const rogue = { levelFor: () => value } as unknown as AssurancePolicy;

      expect(resolveCredentialAssurance(rogue, credential('https://issuer.example'))).toBe('low');
    }
  );

  it('passes key-storage evidence through to the policy unchanged', () => {
    const levelFor = vi.fn(() => 'high' as const);
    const spy: AssurancePolicy = { levelFor };
    const subject = credential('https://issuer.example');

    resolveCredentialAssurance(spy, subject, { keyStorage: 'hardware' });

    expect(levelFor).toHaveBeenCalledWith(subject, { keyStorage: 'hardware' });
  });
});
