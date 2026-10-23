import { describe, expect, it } from 'vitest';

import { BoundedCache } from './bounded-cache';

describe('BoundedCache', () => {
  it('evicts the least recently used entry past its limit', () => {
    const evicted: string[] = [];
    const cache = new BoundedCache<string, string>(2, (value) => evicted.push(value));

    cache.set('a', 'A');
    cache.set('b', 'B');
    cache.get('a');
    cache.set('c', 'C');

    expect(evicted).toEqual(['B']);
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe('A');
    expect(cache.get('c')).toBe('C');
    expect(cache.size).toBe(2);
  });

  it('replaces an entry without evicting it', () => {
    const evicted: string[] = [];
    const cache = new BoundedCache<string, string>(1, (value) => evicted.push(value));

    cache.set('a', 'A');
    cache.set('a', 'A2');

    expect(cache.get('a')).toBe('A2');
    expect(evicted).toEqual([]);
  });

  it.each([0, -1, 1.5, Number.NaN])('refuses the limit %s', (limit) => {
    expect(() => new BoundedCache(limit)).toThrow(RangeError);
  });
});
