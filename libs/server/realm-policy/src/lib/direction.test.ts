import { describe, expect, it } from 'vitest';

import { compareDirection, sameEntries } from './direction';
import { type Direction, ordered } from './field';

describe('compareDirection', () => {
  it.each([
    ['lower-is-stricter', 10, 5, 'tightening'],
    ['lower-is-stricter', 5, 10, 'loosening'],
    ['higher-is-stricter', 1, 3, 'tightening'],
    ['higher-is-stricter', 3, 1, 'loosening'],
    ['true-is-stricter', false, true, 'tightening'],
    ['true-is-stricter', true, false, 'loosening'],
    ['false-is-stricter', true, false, 'tightening'],
    ['false-is-stricter', false, true, 'loosening'],
    ['subset-is-stricter', ['a', 'b'], ['a'], 'tightening'],
    ['subset-is-stricter', ['a'], ['a', 'b'], 'loosening'],
    ['superset-is-stricter', ['a'], ['a', 'b'], 'tightening'],
    ['superset-is-stricter', ['a', 'b'], ['a'], 'loosening'],
    ['opaque', 'x', 'y', 'neutral'],
    ['opaque', null, 'y', 'neutral'],
  ] as const)('%s: %j to %j is a %s', (direction, before, after, expected) => {
    expect(compareDirection(direction, before, after)).toBe(expected);
  });

  it('places an ordered change by the order, from the loosest value to the strictest', () => {
    const laxity = ordered(['development', 'staging', 'production']);
    expect(compareDirection(laxity, 'development', 'production')).toBe('tightening');
    expect(compareDirection(laxity, 'staging', 'production')).toBe('tightening');
    expect(compareDirection(laxity, 'production', 'staging')).toBe('loosening');
    expect(compareDirection(laxity, 'staging', 'development')).toBe('loosening');
  });

  // Acceptance criterion of #514: an unknown direction yields a loosening.
  it('counts a change under an unknown direction as a loosening', () => {
    for (const direction of [
      'sideways',
      'Lower-is-stricter',
      '',
      { kind: 'unordered' },
      { kind: 'ordered' },
      null,
      undefined,
    ]) {
      expect(compareDirection(direction as unknown as Direction, 1, 2)).toBe('loosening');
      expect(compareDirection(direction as unknown as Direction, 2, 1)).toBe('loosening');
    }
  });

  it('counts a value that does not fit its direction as a loosening', () => {
    expect(compareDirection('lower-is-stricter', 10, '5')).toBe('loosening');
    expect(compareDirection('lower-is-stricter', 10, Number.NaN)).toBe('loosening');
    expect(compareDirection('higher-is-stricter', null, 3)).toBe('loosening');
    expect(compareDirection('true-is-stricter', 'false', true)).toBe('loosening');
    expect(compareDirection('subset-is-stricter', ['a', 'b'], 'a')).toBe('loosening');
    expect(compareDirection('subset-is-stricter', ['a', 'b'], ['a', 1])).toBe('loosening');
    expect(compareDirection('superset-is-stricter', 'a', ['a', 'b'])).toBe('loosening');
  });

  it('counts a value outside an ordered direction as a loosening, either way', () => {
    const laxity = ordered(['development', 'staging', 'production']);
    expect(compareDirection(laxity, 'production', 'test')).toBe('loosening');
    expect(compareDirection(laxity, 'test', 'production')).toBe('loosening');
  });

  it('counts a set change that adds and removes as what the added entry does', () => {
    expect(compareDirection('subset-is-stricter', ['a', 'b'], ['a', 'c'])).toBe('loosening');
    expect(compareDirection('superset-is-stricter', ['a', 'b'], ['a', 'c'])).toBe('loosening');
  });

  it('never calls an unchanged value a tightening of a number or a flag', () => {
    expect(compareDirection('lower-is-stricter', 5, 5)).toBe('loosening');
    expect(compareDirection('true-is-stricter', true, true)).toBe('loosening');
    expect(compareDirection(ordered(['a', 'b']), 'a', 'a')).toBe('loosening');
  });
});

describe('sameEntries', () => {
  it('compares lists of strings as sets', () => {
    expect(sameEntries(['a', 'b'], ['b', 'a'])).toBe(true);
    expect(sameEntries([], [])).toBe(true);
    expect(sameEntries(['a'], ['a', 'b'])).toBe(false);
    expect(sameEntries(['a', 'b'], ['a', 'c'])).toBe(false);
    expect(sameEntries(['a'], 'a')).toBe(false);
  });
});
