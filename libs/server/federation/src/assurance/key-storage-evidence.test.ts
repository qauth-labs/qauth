import { describe, expect, it } from 'vitest';

import {
  ATTACK_POTENTIAL_RESISTANCE_ORDER,
  type AttackPotentialResistance,
} from '../attestation/attack-potential';
import {
  type KeyStorageAssuranceEvidence,
  NO_KEY_STORAGE_ASSURANCE,
} from '../attestation/key-storage-assurance';
import type { ValidatedCredential } from '../oid4vp/validated-credential';
import { ValidatedIssuer } from '../trust/issuer-identity';
import { createIssuerAssurancePolicy } from './credential-assurance';
import {
  DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL,
  keyStorageAtFloor,
  translateKeyStorageAssurance,
} from './key-storage-evidence';

/**
 * D1 / D1a, tested directly (issue #379, ADR-010 §5).
 *
 * The translation is the whole of D1, so it gets its own coverage rather than
 * being exercised only through whatever happens to call it. Every assertion here
 * is about the RULE — the presence of a source is not a level, the unstated
 * floor is the strict one, and nothing unknown ever reads as `'hardware'`.
 */

const HIGH = 'iso_18045_high';
const MODERATE = 'iso_18045_moderate';
const BASIC = 'iso_18045_basic';

function evidence(partial: Partial<KeyStorageAssuranceEvidence> = {}): KeyStorageAssuranceEvidence {
  return { assurance: 'key-attested', keyStorage: HIGH, ...partial };
}

describe('translateKeyStorageAssurance — the one D1 rule', () => {
  it('reads a graded source that clears the default floor as hardware', () => {
    expect(translateKeyStorageAssurance(evidence({ keyStorage: HIGH }))).toEqual({
      keyStorage: 'hardware',
      source: 'key-attested',
      establishedAttackPotential: HIGH,
    });
  });

  it('reads a graded source below the floor as software, not as an absence', () => {
    expect(translateKeyStorageAssurance(evidence({ keyStorage: MODERATE }))).toEqual({
      keyStorage: 'software',
      source: 'key-attested',
      establishedAttackPotential: MODERATE,
    });
  });

  it('honours a floor the entry states instead of the default', () => {
    expect(translateKeyStorageAssurance(evidence({ keyStorage: MODERATE }), MODERATE)).toEqual({
      keyStorage: 'hardware',
      source: 'key-attested',
      establishedAttackPotential: MODERATE,
    });
  });

  it('defaults the unstated floor to iso_18045_high — the STRICT reading', () => {
    expect(DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL).toBe(HIGH);

    // The same evidence, read with and without an explicit floor. An operator
    // who writes `requiresKeyStorage: 'hardware'` and nothing else must get the
    // reading that refuses, never the permissive one.
    const graded = evidence({ keyStorage: BASIC });
    expect(translateKeyStorageAssurance(graded).keyStorage).toBe('software');
    expect(translateKeyStorageAssurance(graded, BASIC).keyStorage).toBe('hardware');
  });

  it('never grants hardware for any grade below the default floor', () => {
    for (const grade of ATTACK_POTENTIAL_RESISTANCE_ORDER) {
      const result = translateKeyStorageAssurance(evidence({ keyStorage: grade }));
      expect(result.keyStorage).toBe(
        grade === DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL ? 'hardware' : 'software'
      );
    }
  });
});

describe('translateKeyStorageAssurance — D1a: issuer-attested qualifies, with its source recorded', () => {
  it('lets the transitive path reach hardware', () => {
    expect(
      translateKeyStorageAssurance({ assurance: 'issuer-attested', keyStorage: HIGH })
    ).toEqual({
      keyStorage: 'hardware',
      source: 'issuer-attested',
      establishedAttackPotential: HIGH,
    });
  });

  it('keeps inherited assurance distinguishable from verified assurance', () => {
    const inherited = translateKeyStorageAssurance({
      assurance: 'issuer-attested',
      keyStorage: HIGH,
    });
    const verified = translateKeyStorageAssurance({
      assurance: 'key-attested',
      keyStorage: HIGH,
    });

    // Same policy value, different provenance. The distinction must survive the
    // translation — it is the whole of D1a's corollary.
    expect(inherited.keyStorage).toBe(verified.keyStorage);
    expect(inherited.source).not.toBe(verified.source);
  });

  it('reports the source even when the evidence establishes no key storage', () => {
    expect(translateKeyStorageAssurance({ assurance: 'issuer-attested' })).toEqual({
      keyStorage: undefined,
      source: 'issuer-attested',
      establishedAttackPotential: undefined,
    });
  });
});

describe('translateKeyStorageAssurance — fail-closed', () => {
  it("never grants anything for assurance 'none'", () => {
    expect(translateKeyStorageAssurance(NO_KEY_STORAGE_ASSURANCE)).toEqual({
      keyStorage: undefined,
      source: 'none',
      establishedAttackPotential: undefined,
    });
  });

  it("never grants anything for 'none' even when a grade is somehow present", () => {
    expect(
      translateKeyStorageAssurance({
        assurance: 'none',
        keyStorage: HIGH,
      } as KeyStorageAssuranceEvidence)
    ).toEqual({ keyStorage: undefined, source: 'none', establishedAttackPotential: undefined });
  });

  it('refuses an absent grade rather than reading it as software', () => {
    expect(translateKeyStorageAssurance({ assurance: 'key-attested' })).toEqual({
      keyStorage: undefined,
      source: 'key-attested',
      establishedAttackPotential: undefined,
    });
  });

  it('refuses an unrecognised grade', () => {
    for (const grade of ['iso_18045_super', 'HIGH', '', 3, null, ['iso_18045_high']]) {
      const result = translateKeyStorageAssurance({
        assurance: 'key-attested',
        keyStorage: grade,
      } as unknown as KeyStorageAssuranceEvidence);

      // The unrecognised grade is DROPPED, not forwarded: an entry stating a
      // lower floor must not get a second chance to make sense of a value this
      // build cannot rank.
      expect(result).toEqual({
        keyStorage: undefined,
        source: 'key-attested',
        establishedAttackPotential: undefined,
      });
    }
  });

  it('never reaches hardware through an unrecognised FLOOR', () => {
    // Inherited from `meetsAttackPotential`, which fails closed on a floor it
    // does not understand: an entry that named a level this build cannot read
    // must not have silently disabled the check it was added to impose. The
    // grade itself is still recognised, so the honest answer is the DOWNGRADE
    // rather than an absence — what is unreadable here is the requirement, not
    // the evidence.
    expect(
      translateKeyStorageAssurance(
        evidence({ keyStorage: HIGH }),
        'iso_18045_supreme' as unknown as AttackPotentialResistance
      )
    ).toEqual({
      keyStorage: 'software',
      source: 'key-attested',
      establishedAttackPotential: HIGH,
    });
  });

  it('refuses an unrecognised assurance source carrying a recognised grade', () => {
    expect(
      translateKeyStorageAssurance({
        assurance: 'hardware',
        keyStorage: HIGH,
      } as unknown as KeyStorageAssuranceEvidence)
    ).toEqual({ keyStorage: undefined, source: 'none', establishedAttackPotential: undefined });
  });

  it('reads a missing or unusable evidence object as nothing established', () => {
    for (const input of [undefined, null, 'key-attested', 42]) {
      expect(translateKeyStorageAssurance(input as unknown as KeyStorageAssuranceEvidence)).toEqual(
        { keyStorage: undefined, source: 'none', establishedAttackPotential: undefined }
      );
    }
  });

  it('returns a frozen result — no caller may edit the translation after the fact', () => {
    expect(Object.isFrozen(translateKeyStorageAssurance(evidence()))).toBe(true);
    expect(Object.isFrozen(translateKeyStorageAssurance(NO_KEY_STORAGE_ASSURANCE))).toBe(true);
  });
});

describe('translateKeyStorageAssurance — what the policy does with the result', () => {
  function credentialFrom(assurance: KeyStorageAssuranceEvidence): ValidatedCredential {
    return {
      queryId: 'pid',
      format: 'dc+sd-jwt',
      credentialType: 'https://credentials.example.com/pid',
      issuer: ValidatedIssuer.fromValidatedPresentation({
        identifier: 'https://issuer.example',
        keyResolution: 'issuer-metadata',
      }),
      claims: Object.freeze({}),
      validity: {},
      assurance: {
        credentialType: 'https://credentials.example.com/pid',
        issuerKeyResolution: 'issuer-metadata',
        issuerSignatureAlgorithm: 'ES256',
        keyBindingAlgorithm: 'ES256',
        disclosedClaimCount: 1,
        statusChecked: 'not-required',
        keyStorageAssurance: assurance,
      },
    };
  }

  const policy = createIssuerAssurancePolicy([
    {
      issuer: 'https://issuer.example',
      assuranceLevel: 'high',
      requiresKeyStorage: 'hardware',
    },
  ]);

  it('makes a hardware-demanding entry GRANT when the evidence proves it', () => {
    const credential = credentialFrom({ assurance: 'key-attested', keyStorage: HIGH });
    const { keyStorage } = translateKeyStorageAssurance(credential.assurance.keyStorageAssurance);

    expect(policy.levelFor(credential, { keyStorage })).toBe('high');
  });

  it("returns 'low' when the evidence is below the floor", () => {
    const credential = credentialFrom({ assurance: 'key-attested', keyStorage: BASIC });
    const { keyStorage } = translateKeyStorageAssurance(credential.assurance.keyStorageAssurance);

    expect(policy.levelFor(credential, { keyStorage })).toBe('low');
  });

  it("returns 'low' when nothing established key storage at all", () => {
    const credential = credentialFrom(NO_KEY_STORAGE_ASSURANCE);
    const { keyStorage } = translateKeyStorageAssurance(credential.assurance.keyStorageAssurance);

    expect(policy.levelFor(credential, { keyStorage })).toBe('low');
  });

  /**
   * The per-entry floor (D1's "operator-stated" half). The app translates ONCE,
   * before the policy has chosen an entry, so the evidence it hands over is read
   * at the DEFAULT floor; an entry stating its own floor re-reads the
   * source-free grade. These assert that the re-read reaches a different answer
   * from the default one, which is the only thing that makes the knob real.
   */
  describe('an entry that states its own floor', () => {
    const lenient = createIssuerAssurancePolicy([
      {
        issuer: 'https://issuer.example',
        assuranceLevel: 'high',
        requiresKeyStorage: 'hardware',
        requiresKeyStorageAttackPotential: MODERATE,
      },
    ]);

    /** Exactly what the app call site passes: both members, from one translation. */
    function evidenceFor(credential: ValidatedCredential) {
      const translated = translateKeyStorageAssurance(credential.assurance.keyStorageAssurance);
      return {
        keyStorage: translated.keyStorage,
        keyStorageAttackPotential: translated.establishedAttackPotential,
      };
    }

    it('GRANTS on a grade the default floor would have refused', () => {
      const credential = credentialFrom({ assurance: 'key-attested', keyStorage: MODERATE });

      // The default reading is the strict one, and it refuses.
      expect(policy.levelFor(credential, evidenceFor(credential))).toBe('low');
      // The entry's own floor is what changes the answer.
      expect(lenient.levelFor(credential, evidenceFor(credential))).toBe('high');
    });

    it('still REFUSES a grade below the floor it stated', () => {
      const credential = credentialFrom({ assurance: 'key-attested', keyStorage: BASIC });

      expect(lenient.levelFor(credential, evidenceFor(credential))).toBe('low');
    });

    it("refuses evidence whose source was 'none', however it is graded", () => {
      // The source gate runs before the grade is ever recorded, so a lowered
      // floor cannot resurrect evidence no source established. This is the
      // smuggling path the source-free grade would open if it were read straight
      // off the credential instead of off the translation.
      const credential = credentialFrom({
        assurance: 'none',
        keyStorage: HIGH,
      } as KeyStorageAssuranceEvidence);

      expect(evidenceFor(credential).keyStorageAttackPotential).toBeUndefined();
      expect(lenient.levelFor(credential, evidenceFor(credential))).toBe('low');
    });

    it('refuses when the entry names a floor this build cannot read', () => {
      const unreadable = createIssuerAssurancePolicy([
        {
          issuer: 'https://issuer.example',
          assuranceLevel: 'high',
          requiresKeyStorage: 'hardware',
          requiresKeyStorageAttackPotential:
            'iso_18045_supreme' as unknown as AttackPotentialResistance,
        },
      ]);
      const credential = credentialFrom({ assurance: 'key-attested', keyStorage: HIGH });

      // A typo in a floor must refuse, never disable the check it was written to
      // impose — inherited from `meetsAttackPotential`.
      expect(unreadable.levelFor(credential, evidenceFor(credential))).toBe('low');
    });
  });
});

/**
 * The grade→storage half of the rule, exercised on its own.
 *
 * It exists as a separate export so the policy can apply an entry's floor
 * without a second copy of the branch. These assertions are what stop the two
 * readings drifting apart.
 */
describe('keyStorageAtFloor', () => {
  it('reads at or above the floor as hardware, below it as software', () => {
    expect(keyStorageAtFloor(HIGH, MODERATE)).toBe('hardware');
    expect(keyStorageAtFloor(MODERATE, MODERATE)).toBe('hardware');
    expect(keyStorageAtFloor(BASIC, MODERATE)).toBe('software');
  });

  it('defaults the unstated floor to the strict reading', () => {
    expect(keyStorageAtFloor(MODERATE)).toBe('software');
    expect(keyStorageAtFloor(DEFAULT_KEY_STORAGE_ATTACK_POTENTIAL)).toBe('hardware');
  });

  it('reads an absent or unrecognised grade as nothing, never as software', () => {
    expect(keyStorageAtFloor(undefined)).toBeUndefined();
    for (const grade of ['iso_18045_super', 'HIGH', '', 3, null]) {
      expect(keyStorageAtFloor(grade as unknown as AttackPotentialResistance)).toBeUndefined();
    }
  });

  it('never reaches hardware through an unrecognised floor', () => {
    expect(
      keyStorageAtFloor(HIGH, 'iso_18045_supreme' as unknown as AttackPotentialResistance)
    ).toBe('software');
  });

  it('agrees with the full translation for every grade and floor', () => {
    // The anti-drift assertion. If `translateKeyStorageAssurance` ever stops
    // delegating, one of these pairs diverges.
    for (const grade of ATTACK_POTENTIAL_RESISTANCE_ORDER) {
      for (const floor of ATTACK_POTENTIAL_RESISTANCE_ORDER) {
        expect(
          translateKeyStorageAssurance(evidence({ keyStorage: grade }), floor).keyStorage
        ).toBe(keyStorageAtFloor(grade, floor));
      }
    }
  });
});
