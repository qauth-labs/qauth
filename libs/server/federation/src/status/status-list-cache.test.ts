import { describe, expect, it } from 'vitest';

import {
  type CachedStatusList,
  createInMemoryStatusListCache,
  NO_STATUS_LIST_CACHE,
} from './status-list-cache';
import type { VerifiedStatusList } from './status-list-token';

const statusList: VerifiedStatusList = Object.freeze({
  bits: 1,
  lst: 'AAAA',
  issuer: 'https://issuer.example',
});

function entry(expiresAtMs: number): CachedStatusList {
  return { statusList, expiresAtMs };
}

describe('createInMemoryStatusListCache (#297)', () => {
  it('stores and returns an entry', () => {
    let clock = 1_000;
    const cache = createInMemoryStatusListCache({ now: () => clock });

    cache.set('https://a.example/1', entry(clock + 5_000));
    expect(cache.get('https://a.example/1')?.statusList).toBe(statusList);

    clock += 1_000;
    expect(cache.get('https://a.example/1')).toBeDefined();
  });

  it('misses on an unknown key', () => {
    expect(createInMemoryStatusListCache().get('https://a.example/1')).toBeUndefined();
  });

  it('expires an entry at its deadline and evicts it', () => {
    let clock = 1_000;
    const cache = createInMemoryStatusListCache({ now: () => clock });
    cache.set('https://a.example/1', entry(clock + 1_000));

    clock = 2_000;
    expect(cache.get('https://a.example/1')).toBeUndefined();
    // A second read must also miss — the expired entry is dropped, not merely
    // hidden, so it cannot occupy a slot forever.
    clock = 1_500;
    expect(cache.get('https://a.example/1')).toBeUndefined();
  });

  it('refuses to store an already-expired entry', () => {
    // Otherwise a status issuer publishing `ttl: 0` could evict live entries
    // for other issuers on every login.
    const cache = createInMemoryStatusListCache({ now: () => 1_000 });
    cache.set('https://a.example/1', entry(1_000));
    expect(cache.get('https://a.example/1')).toBeUndefined();
  });

  it('bounds its size and evicts least-recently-used', () => {
    const cache = createInMemoryStatusListCache({ maxEntries: 2, now: () => 0 });
    cache.set('a', entry(10_000));
    cache.set('b', entry(10_000));

    // Touching `a` makes `b` the least recently used.
    expect(cache.get('a')).toBeDefined();
    cache.set('c', entry(10_000));

    expect(cache.get('a')).toBeDefined();
    expect(cache.get('c')).toBeDefined();
    expect(cache.get('b')).toBeUndefined();
  });

  it('keeps the size bound under a flood of distinct keys', () => {
    // The key is attacker-influenced: every credential names its own URI.
    const cache = createInMemoryStatusListCache({ maxEntries: 4, now: () => 0 });
    for (let index = 0; index < 1_000; index += 1) {
      cache.set(`https://a.example/${index}`, entry(10_000));
    }

    let present = 0;
    for (let index = 0; index < 1_000; index += 1) {
      if (cache.get(`https://a.example/${index}`) !== undefined) present += 1;
    }
    expect(present).toBe(4);
  });

  it.each([0, -1, 1.5, Number.NaN])(
    'falls back to the default cap for maxEntries %s',
    (maxEntries) => {
      const cache = createInMemoryStatusListCache({ maxEntries, now: () => 0 });
      cache.set('a', entry(10_000));
      cache.set('b', entry(10_000));
      expect(cache.get('a')).toBeDefined();
      expect(cache.get('b')).toBeDefined();
    }
  );
});

describe('NO_STATUS_LIST_CACHE (#297)', () => {
  it('never stores and never hits', () => {
    NO_STATUS_LIST_CACHE.set('a', entry(Number.MAX_SAFE_INTEGER));
    expect(NO_STATUS_LIST_CACHE.get('a')).toBeUndefined();
  });
});
