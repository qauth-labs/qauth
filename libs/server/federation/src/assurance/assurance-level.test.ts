import { describe, expect, it } from 'vitest';

import { ASSURANCE_LEVELS, parseAssuranceLevel } from './assurance-level';

describe('parseAssuranceLevel (#237)', () => {
  it.each(['low', 'substantial', 'high'] as const)('accepts %s', (level) => {
    expect(parseAssuranceLevel(level)).toBe(level);
  });

  it.each([
    ['an unknown level', 'medium'],
    ['an upper-cased level', 'HIGH'],
    ['a blank string', ''],
    ['null', null],
    ['undefined', undefined],
    ['a number', 2],
    ['an object', { level: 'high' }],
  ] as const)('returns undefined for %s rather than guessing', (_label, value) => {
    expect(parseAssuranceLevel(value)).toBeUndefined();
  });

  it('never silently substitutes low for an unrecognised value', () => {
    // `undefined` and `'low'` behave identically downstream but mean different
    // things: one is a level that was established, the other a value nobody
    // understood. A caller that wants to conflate them writes `?? 'low'`, which
    // is visible in review.
    expect(parseAssuranceLevel('unrecognised')).not.toBe('low');
  });
});

describe('ASSURANCE_LEVELS (#237)', () => {
  it('lists every level in ascending eIDAS LoA order', () => {
    expect(ASSURANCE_LEVELS).toEqual(['low', 'substantial', 'high']);
  });

  it('is frozen so no caller can widen the vocabulary at run time', () => {
    expect(Object.isFrozen(ASSURANCE_LEVELS)).toBe(true);
  });
});
