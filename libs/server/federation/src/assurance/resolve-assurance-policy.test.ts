import { describe, expect, it } from 'vitest';

import { NO_KEY_STORAGE_ASSURANCE } from '../attestation/key-storage-assurance';
import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { ValidatedIssuer } from '../trust/issuer-identity';
import {
  type AssurancePolicyEnvLike,
  type AssurancePolicyRealmLike,
  resolveAssurancePolicy,
} from './resolve-assurance-policy';

const TEST_VCT = 'https://credentials.example.com/pid';

function credential(identifier: string, credentialType: string = TEST_VCT): ValidatedCredential {
  return {
    queryId: 'pid',
    format: 'dc+sd-jwt',
    credentialType,
    issuer: ValidatedIssuer.fromValidatedPresentation({
      identifier,
      keyResolution: 'issuer-metadata',
    }),
    claims: Object.freeze({}),
    validity: {},
    assurance: {
      credentialType,
      issuerKeyResolution: 'issuer-metadata',
      issuerSignatureAlgorithm: 'ES256',
      keyBindingAlgorithm: 'ES256',
      disclosedClaimCount: 1,
      statusChecked: 'not-required',
      keyStorageAssurance: NO_KEY_STORAGE_ASSURANCE,
    },
  };
}

const ENV: AssurancePolicyEnvLike = {
  OID4VP_ISSUER_ASSURANCE: {
    master: { 'https://issuer.example': { level: 'high' } },
    acme: { 'https://acme-issuer.example': { level: 'substantial', credentialTypes: [TEST_VCT] } },
  },
};

describe('resolveAssurancePolicy (#237, mirrors resolveTrustRegistry)', () => {
  it('applies the env policy for the named realm', () => {
    const policy = resolveAssurancePolicy({ name: 'master' }, ENV);

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('high');
  });

  it('keeps one realm policy from leaking into another', () => {
    // A per-realm policy exists precisely so an issuer assured for one tenant
    // is not assured for every other tenant.
    const acme = resolveAssurancePolicy({ name: 'acme' }, ENV);

    expect(acme.levelFor(credential('https://issuer.example'))).toBe('low');
  });

  it('honours credential-type scoping from config', () => {
    const policy = resolveAssurancePolicy({ name: 'acme' }, ENV);

    expect(policy.levelFor(credential('https://acme-issuer.example', TEST_VCT))).toBe(
      'substantial'
    );
    expect(policy.levelFor(credential('https://acme-issuer.example', 'urn:other'))).toBe('low');
  });

  it.each([
    ['a null realm', null],
    ['an unnamed realm', {}],
    ['a blank realm name', { name: '   ' }],
    ['a realm absent from the map', { name: 'unknown' }],
  ] as const)('assures nothing for %s', (_label, realm) => {
    const policy = resolveAssurancePolicy(realm as AssurancePolicyRealmLike | null, ENV);

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('low');
  });

  it.each([
    ['no env at all', null],
    ['an env with no map', {}],
    ['an env whose map is null', { OID4VP_ISSUER_ASSURANCE: null }],
  ] as const)('assures nothing given %s', (_label, env) => {
    const policy = resolveAssurancePolicy({ name: 'master' }, env as AssurancePolicyEnvLike | null);

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('low');
  });

  it('does not walk the prototype chain for a realm named like an Object member', () => {
    // `OID4VP_ISSUER_ASSURANCE` is JSON an operator wrote; a plain property read
    // for a realm named `constructor` returns something off `Object.prototype`.
    const policy = resolveAssurancePolicy(
      { name: 'constructor' },
      {
        OID4VP_ISSUER_ASSURANCE: { master: { 'https://issuer.example': { level: 'high' } } },
      }
    );

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('low');
  });

  it('lets the realm override the env map, and does not fall back to it', () => {
    const policy = resolveAssurancePolicy(
      {
        name: 'master',
        issuerAssurance: { 'https://realm-issuer.example': { level: 'substantial' } },
      },
      ENV
    );

    expect(policy.levelFor(credential('https://realm-issuer.example'))).toBe('substantial');
    // The env entry for `master` must NOT be consulted: substituting a
    // deployment-wide value for a realm that stated its own policy is how a
    // narrow policy silently becomes a wide one.
    expect(policy.levelFor(credential('https://issuer.example'))).toBe('low');
  });

  it('treats an empty realm policy as "assures nothing", not as "unconfigured"', () => {
    const policy = resolveAssurancePolicy({ name: 'master', issuerAssurance: {} }, ENV);

    expect(policy.levelFor(credential('https://issuer.example'))).toBe('low');
  });

  it.each([
    ['a malformed issuer key', { 'not-a-url': { level: 'high' } }],
    ['an http issuer key', { 'http://issuer.example': { level: 'high' } }],
    ['a bare string value', { 'https://issuer.example': 'high' }],
    ['an array value', { 'https://issuer.example': ['high'] }],
    ['a missing level', { 'https://issuer.example': {} }],
    ['a level of low', { 'https://issuer.example': { level: 'low' } }],
    ['an unknown level', { 'https://issuer.example': { level: 'HIGH' } }],
    [
      'a non-array credentialTypes',
      { 'https://issuer.example': { level: 'high', credentialTypes: TEST_VCT } },
    ],
    [
      'an empty credentialTypes list',
      { 'https://issuer.example': { level: 'high', credentialTypes: [] } },
    ],
    [
      'a blank credential type',
      { 'https://issuer.example': { level: 'high', credentialTypes: ['  '] } },
    ],
    ['a top-level array', ['https://issuer.example']],
    ['a top-level null', null],
    [
      'a floor with no key-storage requirement at all',
      {
        'https://issuer.example': {
          level: 'high',
          requiresKeyStorageAttackPotential: 'iso_18045_moderate',
        },
      },
    ],
    [
      'a floor beside a SOFTWARE requirement, in which it decides nothing',
      {
        'https://issuer.example': {
          level: 'high',
          requiresKeyStorage: 'software',
          requiresKeyStorageAttackPotential: 'iso_18045_moderate',
        },
      },
    ],
    [
      'an unreadable key-storage requirement',
      { 'https://issuer.example': { level: 'high', requiresKeyStorage: 'HARDWARE' } },
    ],
    [
      'a floor this build does not rank',
      {
        'https://issuer.example': {
          level: 'high',
          requiresKeyStorage: 'hardware',
          requiresKeyStorageAttackPotential: 'iso_18045_ultra',
        },
      },
    ],
  ] as const)('discards the WHOLE realm policy when it contains %s', (_label, configured) => {
    // All-or-nothing, matching `resolveTrustRegistry`. Honouring the entries
    // that happened to parse would apply an assurance policy the operator never
    // wrote, with no signal that it had been altered.
    const policy = resolveAssurancePolicy({ name: 'master' }, {
      OID4VP_ISSUER_ASSURANCE: {
        master: {
          'https://good.example': { level: 'high' },
          ...(typeof configured === 'object' && configured !== null && !Array.isArray(configured)
            ? configured
            : {}),
        },
      },
    } as unknown as AssurancePolicyEnvLike);

    if (typeof configured === 'object' && configured !== null && !Array.isArray(configured)) {
      expect(policy.levelFor(credential('https://good.example'))).toBe('low');
    }

    const whole = resolveAssurancePolicy({ name: 'master' }, {
      OID4VP_ISSUER_ASSURANCE: { master: configured },
    } as unknown as AssurancePolicyEnvLike);
    expect(whole.levelFor(credential('https://issuer.example'))).toBe('low');
    expect(whole.levelFor(credential('https://good.example'))).toBe('low');
  });

  /**
   * The key-storage half, admitted rather than discarded (#379).
   *
   * The table above is a fail-closed list, so on its own it cannot tell "this
   * shape is refused" from "no shape is ever accepted". These are the two
   * legitimate authorings, pinned so the tightening for the review's finding 1
   * cannot quietly become a ban on the knob it was narrowing.
   */
  describe('the key-storage requirement it DOES admit', () => {
    function policyWith(statement: Record<string, unknown>) {
      return resolveAssurancePolicy({ name: 'master' }, {
        OID4VP_ISSUER_ASSURANCE: {
          master: { 'https://issuer.example': { level: 'high', ...statement } },
        },
      } as unknown as AssurancePolicyEnvLike);
    }

    it('accepts a bare hardware requirement and enforces it', () => {
      const policy = policyWith({ requiresKeyStorage: 'hardware' });

      expect(
        policy.levelFor(credential('https://issuer.example'), { keyStorage: 'hardware' })
      ).toBe('high');
      expect(
        policy.levelFor(credential('https://issuer.example'), { keyStorage: 'software' })
      ).toBe('low');
    });

    it('accepts a bare software requirement', () => {
      expect(
        policyWith({ requiresKeyStorage: 'software' }).levelFor(
          credential('https://issuer.example'),
          { keyStorage: 'software' }
        )
      ).toBe('high');
    });

    it('accepts a floor beside a HARDWARE requirement and reads evidence at it', () => {
      const policy = policyWith({
        requiresKeyStorage: 'hardware',
        requiresKeyStorageAttackPotential: 'iso_18045_moderate',
      });

      // The whole of the knob: the same graded evidence, refused at the strict
      // default and granted at the floor the entry states.
      expect(
        policy.levelFor(credential('https://issuer.example'), {
          keyStorageAttackPotential: 'iso_18045_moderate',
        })
      ).toBe('high');
      expect(
        policyWith({ requiresKeyStorage: 'hardware' }).levelFor(
          credential('https://issuer.example'),
          { keyStorageAttackPotential: 'iso_18045_moderate' }
        )
      ).toBe('low');
    });
  });
});
