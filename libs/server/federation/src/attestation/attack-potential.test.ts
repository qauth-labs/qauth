import { describe, expect, it } from 'vitest';

import {
  ATTACK_POTENTIAL_RESISTANCE_ORDER,
  isAttackPotentialResistance,
  meetsAttackPotential,
  rankAttackPotentialResistance,
  reduceAttackPotentialClaim,
} from './attack-potential';

describe('Attack Potential Resistance (OID4VCI Appendix D §D.2, #308)', () => {
  it('spells the four levels exactly as the specification does', () => {
    // The hyphen in `enhanced-basic` is the one member whose shape differs from
    // the rest, and the one a future edit is most likely to "tidy" into
    // `enhanced_basic`. A near-miss would silently become an unrecognised level.
    expect([...ATTACK_POTENTIAL_RESISTANCE_ORDER]).toEqual([
      'iso_18045_basic',
      'iso_18045_enhanced-basic',
      'iso_18045_moderate',
      'iso_18045_high',
    ]);
  });

  it('is frozen, so the order a policy compares against cannot be reordered', () => {
    expect(Object.isFrozen(ATTACK_POTENTIAL_RESISTANCE_ORDER)).toBe(true);
  });

  describe('rankAttackPotentialResistance', () => {
    it('ranks the levels strongest highest', () => {
      expect(rankAttackPotentialResistance('iso_18045_high')).toBeGreaterThan(
        rankAttackPotentialResistance('iso_18045_moderate') as number
      );
      expect(rankAttackPotentialResistance('iso_18045_moderate')).toBeGreaterThan(
        rankAttackPotentialResistance('iso_18045_enhanced-basic') as number
      );
      expect(rankAttackPotentialResistance('iso_18045_enhanced-basic')).toBeGreaterThan(
        rankAttackPotentialResistance('iso_18045_basic') as number
      );
    });

    it.each([
      ['an invented level', 'iso_18045_ultra'],
      ['a near-miss spelling', 'iso_18045_enhanced_basic'],
      ['a different case', 'ISO_18045_HIGH'],
      ['a number', 4],
      ['null', null],
      ['undefined', undefined],
      ['an object', { level: 'iso_18045_high' }],
    ])('refuses to rank %s', (_label, value) => {
      // An unrecognised level is an UNEVALUATED one. Ranking it — at any
      // position — would let an ecosystem's private vocabulary participate in a
      // comparison this verifier cannot actually make.
      expect(rankAttackPotentialResistance(value)).toBeUndefined();
      expect(isAttackPotentialResistance(value)).toBe(false);
    });
  });

  describe('meetsAttackPotential — fail-closed on every uncertainty', () => {
    it('accepts an equal level and a stronger one', () => {
      expect(meetsAttackPotential('iso_18045_high', 'iso_18045_high')).toBe(true);
      expect(meetsAttackPotential('iso_18045_high', 'iso_18045_moderate')).toBe(true);
    });

    it('refuses a weaker level', () => {
      expect(meetsAttackPotential('iso_18045_moderate', 'iso_18045_high')).toBe(false);
      expect(meetsAttackPotential('iso_18045_basic', 'iso_18045_enhanced-basic')).toBe(false);
    });

    it('refuses an absent level', () => {
      expect(meetsAttackPotential(undefined, 'iso_18045_basic')).toBe(false);
    });

    it('refuses an unrecognised level rather than treating it as the weakest known', () => {
      expect(meetsAttackPotential('iso_18045_ultra', 'iso_18045_basic')).toBe(false);
    });

    it('refuses EVERYTHING when the floor itself is unrecognised', () => {
      // The direction that matters most. If a typo in a profile table produced
      // an unreadable floor and this returned `true`, the typo would silently
      // DISABLE the check it was added to impose — the failure mode a
      // fail-closed comparison exists to prevent.
      expect(meetsAttackPotential('iso_18045_high', 'iso_18045_hihg')).toBe(false);
      expect(meetsAttackPotential('iso_18045_high', undefined)).toBe(false);
    });
  });

  describe('reduceAttackPotentialClaim — a list resists its WEAKEST member', () => {
    it('reads a single-level claim', () => {
      expect(reduceAttackPotentialClaim(['iso_18045_high'])).toBe('iso_18045_high');
    });

    it('takes the weakest of several, never the strongest', () => {
      // Taking the maximum would let any wallet clear any floor by appending
      // `iso_18045_high` to a list that also describes a basic-resistance path.
      expect(reduceAttackPotentialClaim(['iso_18045_high', 'iso_18045_basic'])).toBe(
        'iso_18045_basic'
      );
      expect(reduceAttackPotentialClaim(['iso_18045_basic', 'iso_18045_high'])).toBe(
        'iso_18045_basic'
      );
    });

    it('is poisoned by a single unrecognised entry', () => {
      // The unknown entry may describe a weaker path, and this verifier cannot
      // tell. Reading past it would mean reporting a level the claim does not
      // support.
      expect(reduceAttackPotentialClaim(['iso_18045_high', 'iso_18045_ultra'])).toBeUndefined();
    });

    it.each([
      ['an empty array', []],
      ['a bare string', 'iso_18045_high'],
      ['null', null],
      ['undefined', undefined],
      ['an object', { key_storage: 'iso_18045_high' }],
    ])('establishes nothing from %s', (_label, value) => {
      expect(reduceAttackPotentialClaim(value)).toBeUndefined();
    });
  });
});
