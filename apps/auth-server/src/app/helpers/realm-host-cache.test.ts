import { describe, expect, it, vi } from 'vitest';

import {
  createRealmHostCache,
  REALM_HOST_CACHE_TTL_MS,
  REALM_HOST_MISS_TTL_MS,
  type RealmHostLookup,
  type RealmHostMatch,
} from './realm-host-cache';

/** A `realm_hosts` match for `host`, enough for the cache, which never reads the realm. */
function matchFor(host: string, kind: 'primary' | 'endpoint' = 'primary'): RealmHostMatch {
  return {
    realm: { id: `realm-of-${host}`, name: host, enabled: true, issuer: `https://${host}` },
    host: { host, realmId: `realm-of-${host}`, kind, createdAt: 0 },
  } as RealmHostMatch;
}

/** A host table the test edits, behind a lookup that counts its calls. */
function hostTable(initial: Record<string, RealmHostMatch> = {}) {
  const rows = new Map(Object.entries(initial));
  const lookup = vi.fn<RealmHostLookup>(async (host) => rows.get(host));
  return { rows, lookup };
}

/** A clock the test moves by hand. */
function manualClock(start = 1_000_000) {
  let at = start;
  return {
    now: () => at,
    advance(ms: number) {
      at += ms;
    },
  };
}

describe('realm host cache (#486)', () => {
  it('keeps a host that names a realm for 30 seconds by default', async () => {
    const clock = manualClock();
    const { rows, lookup } = hostTable({ 'auth.example.com': matchFor('auth.example.com') });
    const cache = createRealmHostCache({ lookup, now: clock.now });

    expect(await cache.resolve('auth.example.com')).toEqual(matchFor('auth.example.com'));
    rows.delete('auth.example.com');

    clock.advance(REALM_HOST_CACHE_TTL_MS - 1);
    expect(await cache.resolve('auth.example.com')).toEqual(matchFor('auth.example.com'));
    expect(lookup).toHaveBeenCalledTimes(1);

    clock.advance(1);
    expect(await cache.resolve('auth.example.com')).toBeUndefined();
    expect(lookup).toHaveBeenCalledTimes(2);
    expect(REALM_HOST_CACHE_TTL_MS).toBe(30_000);
  });

  it('makes a new endpoint host visible within the 5 second miss time', async () => {
    const clock = manualClock();
    const { rows, lookup } = hostTable();
    const cache = createRealmHostCache({ lookup, now: clock.now });

    expect(await cache.resolve('auth-server')).toBeUndefined();
    rows.set('auth-server', matchFor('auth-server', 'endpoint'));

    clock.advance(REALM_HOST_MISS_TTL_MS - 1);
    expect(await cache.resolve('auth-server')).toBeUndefined();

    clock.advance(1);
    expect(await cache.resolve('auth-server')).toEqual(matchFor('auth-server', 'endpoint'));
    expect(lookup).toHaveBeenCalledTimes(2);
    expect(REALM_HOST_MISS_TTL_MS).toBe(5_000);
  });

  it('never keeps a miss longer than a hit', async () => {
    const clock = manualClock();
    const { rows, lookup } = hostTable();
    const cache = createRealmHostCache({ lookup, now: clock.now, ttlMs: 1_000 });

    expect(await cache.resolve('auth-server')).toBeUndefined();
    rows.set('auth-server', matchFor('auth-server', 'endpoint'));
    clock.advance(1_000);

    expect(await cache.resolve('auth-server')).toEqual(matchFor('auth-server', 'endpoint'));
  });

  it('shares one lookup between concurrent requests for the same host', async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const lookup = vi.fn<RealmHostLookup>(async (host) => {
      await gate;
      return matchFor(host);
    });
    const cache = createRealmHostCache({ lookup });

    const answers = Promise.all([
      cache.resolve('auth.example.com'),
      cache.resolve('auth.example.com'),
      cache.resolve('auth.example.com'),
    ]);
    release?.();

    expect(await answers).toEqual([
      matchFor('auth.example.com'),
      matchFor('auth.example.com'),
      matchFor('auth.example.com'),
    ]);
    expect(lookup).toHaveBeenCalledTimes(1);
  });

  it('does not cache a lookup that fails, even one that throws at once', async () => {
    const lookup = vi
      .fn<RealmHostLookup>()
      .mockImplementationOnce(() => {
        throw new Error('connection refused');
      })
      .mockImplementationOnce(async () => {
        throw new Error('connection refused');
      })
      .mockImplementation(async (host) => matchFor(host));
    const cache = createRealmHostCache({ lookup });

    await expect(cache.resolve('auth.example.com')).rejects.toThrow('connection refused');
    await expect(cache.resolve('auth.example.com')).rejects.toThrow('connection refused');
    expect(await cache.resolve('auth.example.com')).toEqual(matchFor('auth.example.com'));
    expect(lookup).toHaveBeenCalledTimes(3);
  });

  it('bounds the misses without letting them push the hits out', async () => {
    const { lookup } = hostTable({ 'auth.example.com': matchFor('auth.example.com') });
    const cache = createRealmHostCache({ lookup, maxEntries: 3 });

    await cache.resolve('auth.example.com');
    for (let i = 0; i < 10; i += 1) await cache.resolve(`unknown-${i}.example`);
    lookup.mockClear();

    expect(await cache.resolve('auth.example.com')).toEqual(matchFor('auth.example.com'));
    expect(lookup).not.toHaveBeenCalled();
    // Only the three newest misses are left.
    await cache.resolve('unknown-9.example');
    expect(lookup).not.toHaveBeenCalled();
    await cache.resolve('unknown-0.example');
    expect(lookup).toHaveBeenCalledWith('unknown-0.example');
  });

  it('does not store, or share, a lookup that was running when clear() was called', async () => {
    let release: (() => void) | undefined;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const { rows, lookup } = hostTable({ 'auth.example.com': matchFor('auth.example.com') });
    // The first lookup answers with the row as it was, after clear() ran.
    lookup.mockImplementationOnce(async (host) => {
      await gate;
      return matchFor(host);
    });
    const cache = createRealmHostCache({ lookup });

    const before = cache.resolve('auth.example.com');
    cache.clear();
    rows.delete('auth.example.com');
    const after = cache.resolve('auth.example.com');
    release?.();

    expect(await before).toEqual(matchFor('auth.example.com'));
    expect(await after).toBeUndefined();
    expect(await cache.resolve('auth.example.com')).toBeUndefined();
    expect(lookup).toHaveBeenCalledTimes(2);
  });

  it('forgets everything on clear()', async () => {
    const { lookup } = hostTable({ 'auth.example.com': matchFor('auth.example.com') });
    const cache = createRealmHostCache({ lookup });

    await cache.resolve('auth.example.com');
    await cache.resolve('unknown.example');
    cache.clear();
    await cache.resolve('auth.example.com');
    await cache.resolve('unknown.example');

    expect(lookup).toHaveBeenCalledTimes(4);
  });
});
