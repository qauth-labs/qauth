import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { ValidatedIssuer } from '../trust/issuer-identity';
import {
  type AttestingIssuerEntry,
  createStaticAttestingIssuers,
  NO_ATTESTING_ISSUERS,
  strongestAttestedKeyStorage,
} from './attesting-issuers';

/** A validated issuer identity, built the only way #234 can build one. */
function validated(identifier: string): ValidatedIssuer {
  return ValidatedIssuer.fromValidatedPresentation({
    identifier,
    keyResolution: 'x5c',
  });
}

const ENTRIES: readonly AttestingIssuerEntry[] = [
  { issuer: 'https://pid.issuer.example', keyStorage: 'iso_18045_high' },
  { issuer: 'https://mdl.issuer.example/', keyStorage: 'iso_18045_moderate' },
];

describe('KeyStorageAttestingIssuers — the transitive WSCD path (#308, HAIP §4.5.1)', () => {
  describe('NO_ATTESTING_ISSUERS', () => {
    it('records nothing, so an unconfigured deployment establishes nothing', () => {
      expect(
        NO_ATTESTING_ISSUERS.attestedKeyStorage(validated('https://pid.issuer.example'))
      ).toBeUndefined();
    });

    it('is frozen, so "nothing is recorded" cannot be edited into "something is"', () => {
      expect(Object.isFrozen(NO_ATTESTING_ISSUERS)).toBe(true);
    });
  });

  describe('createStaticAttestingIssuers', () => {
    it('returns the level the operator recorded for an issuer', () => {
      const registry = createStaticAttestingIssuers(ENTRIES);

      expect(registry.attestedKeyStorage(validated('https://pid.issuer.example'))).toBe(
        'iso_18045_high'
      );
      expect(registry.attestedKeyStorage(validated('https://mdl.issuer.example'))).toBe(
        'iso_18045_moderate'
      );
    });

    it('canonicalizes BOTH sides, so a trailing slash is not a different issuer', () => {
      // The entry carries a trailing slash and the validated identity does not.
      // If only one side were reduced, the operator's configuration would
      // silently stop matching.
      const registry = createStaticAttestingIssuers([
        { issuer: 'https://pid.issuer.example/', keyStorage: 'iso_18045_high' },
      ]);

      expect(registry.attestedKeyStorage(validated('https://pid.issuer.example'))).toBe(
        'iso_18045_high'
      );
    });

    it('records nothing about an issuer the operator did not list', () => {
      const registry = createStaticAttestingIssuers(ENTRIES);

      expect(
        registry.attestedKeyStorage(validated('https://other.issuer.example'))
      ).toBeUndefined();
    });

    it('refuses a FORGED issuer identity even when its identifier is listed', () => {
      // The whole point of the nominal `ValidatedIssuer`: an object with the
      // right fields is not an issuer this presentation actually validated. A
      // backend is a trust boundary in its own right and re-checks the brand
      // rather than inheriting the caller's assumptions.
      const registry = createStaticAttestingIssuers(ENTRIES);
      const forged = {
        identifier: 'https://pid.issuer.example',
        keyResolution: 'x5c',
      } as unknown as ValidatedIssuer;

      expect(registry.attestedKeyStorage(forged)).toBeUndefined();
    });

    it('is empty-safe: no entries records nothing rather than everything', () => {
      const registry = createStaticAttestingIssuers([]);

      expect(registry.attestedKeyStorage(validated('https://pid.issuer.example'))).toBeUndefined();
    });

    it.each([
      [
        'a non-HTTPS identifier',
        { issuer: 'http://pid.issuer.example', keyStorage: 'iso_18045_high' },
      ],
      [
        'an identifier with userinfo',
        { issuer: 'https://u:p@pid.example', keyStorage: 'iso_18045_high' },
      ],
      [
        'an identifier with a query string',
        { issuer: 'https://pid.example?x=1', keyStorage: 'iso_18045_high' },
      ],
      ['a non-string identifier', { issuer: 42, keyStorage: 'iso_18045_high' }],
      ['a missing identifier', { keyStorage: 'iso_18045_high' }],
    ])('throws InvalidConfigurationError for %s', (_label, entry) => {
      // An OPERATOR error, thrown rather than dropped: a dropped entry leaves
      // the operator believing an ecosystem's key storage is recognised when it
      // is not, which surfaces as every user of that wallet quietly losing
      // assurance.
      expect(() =>
        createStaticAttestingIssuers([entry as unknown as AttestingIssuerEntry])
      ).toThrow(InvalidConfigurationError);
    });

    it.each([
      ['an invented level', 'iso_18045_ultra'],
      ['a near-miss spelling', 'iso_18045_enhanced_basic'],
      ['a missing level', undefined],
    ])('throws InvalidConfigurationError for %s', (_label, keyStorage) => {
      expect(() =>
        createStaticAttestingIssuers([
          { issuer: 'https://pid.issuer.example', keyStorage } as AttestingIssuerEntry,
        ])
      ).toThrow(InvalidConfigurationError);
    });

    it('reports the offending entry on details, never in the message', () => {
      try {
        createStaticAttestingIssuers([{ issuer: 'not-a-url', keyStorage: 'iso_18045_high' }]);
        expect.fail('a malformed entry must be refused');
      } catch (error) {
        expect(error).toBeInstanceOf(InvalidConfigurationError);
        expect((error as InvalidConfigurationError).message).not.toContain('not-a-url');
        expect((error as InvalidConfigurationError).details?.['index']).toBe(0);
      }
    });

    it('refuses a non-array outright', () => {
      expect(() => createStaticAttestingIssuers(undefined as never)).toThrow(
        InvalidConfigurationError
      );
    });

    it('is frozen, so a request handler cannot widen it process-wide', () => {
      expect(Object.isFrozen(createStaticAttestingIssuers(ENTRIES))).toBe(true);
    });
  });
});

/**
 * The aggregate the BOOT gate reads (#379 review, finding 3).
 *
 * `assertKeyStorageAssuranceProvisioned` used to be handed a boolean, so a
 * registry recording only `iso_18045_basic` issuers answered "provisioned" for a
 * `haip-1.0` deployment whose declared floor is `iso_18045_high` — it booted and
 * then refused every presentation with `attack-potential-below-minimum`, the
 * same 100%-failure outcome as provisioning nothing. This is what replaced the
 * boolean.
 */
describe('strongestAttestedKeyStorage (#308/#379)', () => {
  it('is undefined for an empty, absent or non-array set', () => {
    for (const entries of [[], undefined, null, 'x', 3]) {
      expect(
        strongestAttestedKeyStorage(entries as readonly AttestingIssuerEntry[])
      ).toBeUndefined();
    }
  });

  it('reports the single recorded grade', () => {
    expect(
      strongestAttestedKeyStorage([
        { issuer: 'https://pid.issuer.example', keyStorage: 'iso_18045_moderate' },
      ])
    ).toBe('iso_18045_moderate');
  });

  it('reports the STRONGEST, not the first, the last or the weakest', () => {
    // The gate asks whether the deployment can clear the floor for ANY recorded
    // ecosystem. A registry mixing a strong issuer with a weak one is a working
    // deployment with one weak ecosystem, and refusing to start on it would be
    // wrong — so the aggregate must not be the minimum.
    expect(
      strongestAttestedKeyStorage([
        { issuer: 'https://a.example', keyStorage: 'iso_18045_moderate' },
        { issuer: 'https://b.example', keyStorage: 'iso_18045_high' },
        { issuer: 'https://c.example', keyStorage: 'iso_18045_basic' },
      ])
    ).toBe('iso_18045_high');
  });

  it('is order-independent', () => {
    const forwards = strongestAttestedKeyStorage([
      { issuer: 'https://a.example', keyStorage: 'iso_18045_basic' },
      { issuer: 'https://b.example', keyStorage: 'iso_18045_high' },
    ]);
    const backwards = strongestAttestedKeyStorage([
      { issuer: 'https://b.example', keyStorage: 'iso_18045_high' },
      { issuer: 'https://a.example', keyStorage: 'iso_18045_basic' },
    ]);

    expect(forwards).toBe('iso_18045_high');
    expect(backwards).toBe(forwards);
  });

  it('SKIPS a grade this build cannot read rather than throwing', () => {
    // `createStaticAttestingIssuers`, run at boot through
    // `assertAttestingIssuersUsable`, is the one place a grade this build cannot
    // read takes the deployment down — naming the position and the value. A
    // second, differently-worded refusal for the same typo would be worse than
    // useless.
    expect(
      strongestAttestedKeyStorage([
        { issuer: 'https://a.example', keyStorage: 'ISO_18045_HIGH' as never },
        { issuer: 'https://b.example', keyStorage: 'iso_18045_moderate' },
      ])
    ).toBe('iso_18045_moderate');
  });

  it('is undefined when every recorded grade is unreadable', () => {
    expect(
      strongestAttestedKeyStorage([
        { issuer: 'https://a.example', keyStorage: 'high' as never },
        { issuer: 'https://b.example', keyStorage: undefined as never },
      ])
    ).toBeUndefined();
  });

  it('tolerates a hole in the array without throwing', () => {
    expect(
      strongestAttestedKeyStorage([
        undefined as unknown as AttestingIssuerEntry,
        { issuer: 'https://b.example', keyStorage: 'iso_18045_high' },
      ])
    ).toBe('iso_18045_high');
  });

  it('does not enumerate the registry to answer — it reads the ENTRIES', () => {
    // The opacity of `KeyStorageAttestingIssuers` is a deliberate property: no
    // error message can be built from its contents. This function must not have
    // been the thing that broke it.
    expect(Object.keys(createStaticAttestingIssuers(ENTRIES))).toEqual(['attestedKeyStorage']);
  });
});
