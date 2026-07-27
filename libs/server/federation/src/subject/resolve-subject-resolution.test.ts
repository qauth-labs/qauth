import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { validatedFixtureCredential } from '../../testing/subject-resolution.fixture';
import { VERIFIER_PROFILES } from '../profiles/verifier-profiles';
import {
  resolveSubjectResolution,
  resolveSubjectResolutionStrategyId,
  type SubjectResolutionEnvLike,
} from './resolve-subject-resolution';
import { deriveIssuerScopedSubject, deriveWalletBinding } from './subject-binding';
import type { SubjectAccountLookup } from './subject-resolution.types';
import { createSubjectResolutionStrategy } from './subject-resolution-strategies';

/**
 * Selecting and configuring the strategy (#300, ADR-009).
 *
 * The shape mirrors `resolve-verifier-profile.test.ts` because the resolver
 * mirrors that resolver: realm first, env as the deployment-wide default,
 * all-or-nothing realm selection, and two distinguishable refusals.
 */

const BASE = VERIFIER_PROFILES['oid4vp-1.0-base'];
const BINDING_CLAIMS = ['family_name', 'given_name'];

function envOf(overrides: SubjectResolutionEnvLike = {}): SubjectResolutionEnvLike {
  return { OID4VP_SUBJECT_BINDING_CLAIMS: BINDING_CLAIMS, ...overrides };
}

describe('resolveSubjectResolutionStrategyId (issue #300)', () => {
  it('falls back to the profile default when nothing is configured', () => {
    // ADR-009 §1: `asserted-lookup` is the default, and BOTH shipped profiles
    // declare it — the EUDI-aligned one included, because the PID carries no
    // usable persistent identifier (Finding 1).
    expect(resolveSubjectResolutionStrategyId(null, null, BASE)).toBe('asserted-lookup');
    expect(resolveSubjectResolutionStrategyId(null, null, VERIFIER_PROFILES['haip-1.0'])).toBe(
      'asserted-lookup'
    );
  });

  it('lets the deployment override the profile default', () => {
    expect(
      resolveSubjectResolutionStrategyId(
        null,
        { OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim' },
        BASE
      )
    ).toBe('issuer-scoped-claim');
  });

  it('lets the realm override the deployment', () => {
    expect(
      resolveSubjectResolutionStrategyId(
        { subjectResolution: 'issuer-scoped-claim' },
        { OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup' },
        BASE
      )
    ).toBe('issuer-scoped-claim');
  });

  it('refuses a realm value it does not recognise, and does NOT consult the env', () => {
    // All-or-nothing, exactly as #299 does it: a realm row meant to run one
    // account-keying model with a typo'd value must not silently run another.
    expect(
      resolveSubjectResolutionStrategyId(
        { subjectResolution: 'asserted_lookup' },
        { OID4VP_SUBJECT_RESOLUTION: 'asserted-lookup' },
        BASE
      )
    ).toBeUndefined();
  });

  it('refuses an env value it does not recognise, and does NOT fall back to the profile', () => {
    expect(
      resolveSubjectResolutionStrategyId(null, { OID4VP_SUBJECT_RESOLUTION: 'nonsense' }, BASE)
    ).toBeUndefined();
  });

  it.each(['session-binding', 'key-thumbprint', 'rp-pseudonym'])(
    "throws rather than silently accepting '%s'",
    (strategy) => {
      // Half-configured, not unconfigured: the operator asked for something real
      // and gets the gate explained, not a `undefined` that reads as "you
      // selected nothing".
      expect(() =>
        resolveSubjectResolutionStrategyId(null, { OID4VP_SUBJECT_RESOLUTION: strategy }, BASE)
      ).toThrow(InvalidConfigurationError);
    }
  );

  it('applies the same gate to a PROFILE default as to an operator value', () => {
    // A future profile defaulting to a gated strategy must fail the boot, not be
    // honoured because the table said so.
    expect(() =>
      resolveSubjectResolutionStrategyId(null, null, { defaultSubjectResolution: 'rp-pseudonym' })
    ).toThrow(InvalidConfigurationError);
  });

  it('refuses a profile whose default is not a strategy at all', () => {
    expect(
      resolveSubjectResolutionStrategyId(null, null, {
        defaultSubjectResolution: 'invented' as never,
      })
    ).toBeUndefined();
  });
});

describe('resolveSubjectResolution — the fully-specified configuration', () => {
  it('builds asserted-lookup from the configured binding claims', () => {
    expect(resolveSubjectResolution(null, envOf(), BASE)).toEqual({
      strategy: 'asserted-lookup',
      bindingClaims: BINDING_CLAIMS,
    });
  });

  it('refuses a deployment that configured NOTHING — the default still needs its check', () => {
    // The intended outcome for "the operator configured nothing": ADR-009 §1's
    // entitlement check is what stops any valid credential authenticating any
    // account, so its absence must be a refusal rather than a strategy that
    // authenticates everyone. Refused HERE, not at construction, so a
    // configuration this resolver returns is always buildable.
    expect(() => resolveSubjectResolution(null, null, BASE)).toThrow(InvalidConfigurationError);
  });

  it('builds issuer-scoped-claim with the MANDATORY fallback wired in', () => {
    // ADR-009 §2 requires the fallback unconditionally, so the resolver cannot
    // produce a configuration without one.
    expect(
      resolveSubjectResolution(
        null,
        envOf({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_CLAIM: 'employee_number',
          OID4VP_SUBJECT_CLAIM_ISSUERS: ['https://hr.example.com'],
        }),
        BASE
      )
    ).toEqual({
      strategy: 'issuer-scoped-claim',
      subjectClaim: 'employee_number',
      issuers: ['https://hr.example.com'],
      fallback: { bindingClaims: BINDING_CLAIMS },
    });
  });

  it.each([
    ['no subject claim', {}],
    ['an empty subject claim', { OID4VP_SUBJECT_CLAIM: '' }],
  ])('refuses issuer-scoped-claim with %s', (_label, extra) => {
    expect(() =>
      resolveSubjectResolution(
        null,
        envOf({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_CLAIM_ISSUERS: ['https://hr.example.com'],
          ...extra,
        }),
        BASE
      )
    ).toThrow(InvalidConfigurationError);
  });

  it('refuses issuer-scoped-claim with no named issuers', () => {
    // ADR-009 §2 permits the strategy only for a specific, NAMED issuer. An
    // empty opt-in list would silently make every presentation take the
    // fallback, which is a different deployment from the one the operator
    // configured.
    expect(() =>
      resolveSubjectResolution(
        null,
        envOf({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_CLAIM: 'employee_number',
        }),
        BASE
      )
    ).toThrow(InvalidConfigurationError);
  });

  it('refuses iss as the issuer-scoped subject claim, at the config boundary', () => {
    expect(() =>
      resolveSubjectResolution(
        null,
        envOf({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_CLAIM: 'iss',
          OID4VP_SUBJECT_CLAIM_ISSUERS: ['https://hr.example.com'],
        }),
        BASE
      )
    ).toThrow(InvalidConfigurationError);
  });

  it('every configuration it returns is one createSubjectResolutionStrategy can build', () => {
    // The contract that makes the eager validation worth having: a caller that
    // resolved successfully never discovers a configuration problem later, at a
    // presentation.
    const configs = [
      resolveSubjectResolution(null, envOf(), BASE),
      resolveSubjectResolution(
        null,
        envOf({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_CLAIM: 'employee_number',
          OID4VP_SUBJECT_CLAIM_ISSUERS: ['https://hr.example.com'],
        }),
        BASE
      ),
    ];

    expect(configs.map((config) => createSubjectResolutionStrategy(config!).id)).toEqual([
      'asserted-lookup',
      'issuer-scoped-claim',
    ]);
  });

  it('returns undefined — not a default — when the selection is unrecognised', () => {
    expect(
      resolveSubjectResolution(null, envOf({ OID4VP_SUBJECT_RESOLUTION: 'nonsense' }), BASE)
    ).toBeUndefined();
  });
});

describe('switching the configured strategy changes resolution, with no protocol change', () => {
  it('resolves the same presentation differently under the two login strategies', async () => {
    // The #300 acceptance criterion, asserted end to end: one real, validated
    // credential; one account store; two deployments differing ONLY in
    // `OID4VP_SUBJECT_RESOLUTION`. Nothing below names a strategy — both
    // resolvers are handed the same credential through the same interface.
    const credential = await validatedFixtureCredential({
      issuer: 'https://hr.example.com',
      claims: { given_name: 'Alice', family_name: 'Doe', employee_number: 'E-1' },
    });

    const binding = deriveWalletBinding(credential, [...BINDING_CLAIMS].sort()) as string;
    const subject = deriveIssuerScopedSubject(credential, 'employee_number') as string;

    const lookup: SubjectAccountLookup = {
      async byAssertedIdentifier(_realmId, identifier) {
        return identifier === 'alice@example.com'
          ? [{ userId: 'user-by-assertion', walletBinding: binding }]
          : [];
      },
      async byWalletSubject(_realmId, externalSub) {
        return externalSub === subject
          ? [{ userId: 'user-by-issuer-claim', walletBinding: null }]
          : [];
      },
    };
    const context = {
      realmId: 'realm-1',
      assertedIdentifier: 'alice@example.com',
      lookup,
    };

    const asserted = createSubjectResolutionStrategy(
      resolveSubjectResolution(null, envOf(), BASE)!
    );
    const issuerScoped = createSubjectResolutionStrategy(
      resolveSubjectResolution(
        null,
        envOf({
          OID4VP_SUBJECT_RESOLUTION: 'issuer-scoped-claim',
          OID4VP_SUBJECT_CLAIM: 'employee_number',
          OID4VP_SUBJECT_CLAIM_ISSUERS: ['https://hr.example.com'],
        }),
        BASE
      )!
    );

    await expect(asserted.resolve(credential, context)).resolves.toEqual({
      kind: 'matched',
      userId: 'user-by-assertion',
    });
    await expect(issuerScoped.resolve(credential, context)).resolves.toEqual({
      kind: 'matched',
      userId: 'user-by-issuer-claim',
    });
  });
});
