import { beforeEach, describe, expect, it } from 'vitest';

import {
  createRedisSessionCache,
  sessionCacheKey,
  type SessionRedisClient,
  sessionTombstoneKey,
} from './redis-session-cache';
import type { CachedSession } from './types';

const REALM = '0199a000-0000-7000-8000-00000000000a';
const SID = '0199a000-0000-7000-8000-0000000000c1';

/** The three commands, over a map; records each call. */
function fakeRedis() {
  const values = new Map<string, { value: string; px: number }>();
  const calls: string[] = [];
  const client: SessionRedisClient = {
    async mget(...keys) {
      calls.push(`MGET ${keys.join(' ')}`);
      return keys.map((key) => values.get(key)?.value ?? null);
    },
    async set(key, value, mode, milliseconds) {
      calls.push(`SET ${key} ${mode} ${milliseconds}`);
      values.set(key, { value, px: milliseconds });
      return 'OK';
    },
    async del(...keys) {
      calls.push(`DEL ${keys.join(' ')}`);
      return keys.filter((key) => values.delete(key)).length;
    },
  };
  return { client, values, calls };
}

const ENTRY: CachedSession = {
  record: {
    id: SID,
    realmId: REALM,
    userId: '0199a000-0000-7000-8000-0000000000aa',
    authTime: 1_000,
    amr: ['pwd'],
    assuranceLevel: null,
    expiresAt: 90_000,
    createdAt: 1_000,
    lastSeenAt: 1_000,
  },
  lifetimes: { maxLifespanSeconds: null, idleTimeoutSeconds: 600 },
  freshUntil: 61_000,
};

let redis: ReturnType<typeof fakeRedis>;

beforeEach(() => {
  redis = fakeRedis();
});

describe('the Redis session cache', () => {
  it('keys an entry by realm and sid, with the sid as the hash tag', () => {
    expect(sessionCacheKey(REALM, SID)).toBe(`browser-session:${REALM}:{${SID}}`);
    expect(sessionTombstoneKey(REALM, SID)).toBe(`browser-session:${REALM}:{${SID}}:revoked`);
  });

  it('writes an entry with its time to live and reads it back', async () => {
    const cache = createRedisSessionCache(redis.client);

    await cache.write(ENTRY, 60_000);

    expect(redis.calls).toEqual([`SET ${sessionCacheKey(REALM, SID)} PX 60000`]);
    expect(await cache.read(REALM, SID)).toEqual({ kind: 'entry', entry: ENTRY });
    expect(redis.calls[1]).toBe(
      `MGET ${sessionCacheKey(REALM, SID)} ${sessionTombstoneKey(REALM, SID)}`
    );
  });

  it('rounds a time to live up to whole milliseconds, and never to zero', async () => {
    const cache = createRedisSessionCache(redis.client);

    await cache.write(ENTRY, 0.2);
    await cache.markRevoked(REALM, SID, 1500.5);

    expect(redis.calls).toContain(`SET ${sessionCacheKey(REALM, SID)} PX 1`);
    expect(redis.calls).toContain(`SET ${sessionTombstoneKey(REALM, SID)} PX 1501`);
  });

  it('reads nothing for a session it does not hold', async () => {
    expect(await createRedisSessionCache(redis.client).read(REALM, SID)).toEqual({
      kind: 'empty',
    });
  });

  it('writes the tombstone before it deletes the entry, and the tombstone wins', async () => {
    const cache = createRedisSessionCache(redis.client);
    await cache.write(ENTRY, 60_000);
    redis.calls.length = 0;

    await cache.markRevoked(REALM, SID, 60_000);
    expect(redis.calls).toEqual([
      `SET ${sessionTombstoneKey(REALM, SID)} PX 60000`,
      `DEL ${sessionCacheKey(REALM, SID)}`,
    ]);

    // A fill that raced the revocation: the entry is back, and still absent.
    await cache.write(ENTRY, 60_000);
    expect(await cache.read(REALM, SID)).toEqual({ kind: 'revoked' });
  });

  it.each([
    ['not JSON', '{'],
    ['another layout version', JSON.stringify({ ...ENTRY, v: 2 })],
    ['no version', JSON.stringify(ENTRY)],
    ['a wrong-shaped record', JSON.stringify({ ...ENTRY, v: 1, record: { id: SID } })],
    [
      'an unknown assurance level',
      JSON.stringify({ ...ENTRY, v: 1, record: { ...ENTRY.record, assuranceLevel: 'low' } }),
    ],
  ])('reads %s as a miss', async (_name, raw) => {
    redis.values.set(sessionCacheKey(REALM, SID), { value: raw, px: 1 });

    expect(await createRedisSessionCache(redis.client).read(REALM, SID)).toEqual({
      kind: 'empty',
    });
  });

  it('stores the entry’s own fields only', async () => {
    const cache = createRedisSessionCache(redis.client);
    await cache.write({ ...ENTRY, csrfToken: 'x' } as CachedSession, 60_000);

    const stored = JSON.parse(redis.values.get(sessionCacheKey(REALM, SID))?.value ?? '{}');
    expect(Object.keys(stored).sort()).toEqual(['freshUntil', 'lifetimes', 'record', 'v']);
    expect(await cache.read(REALM, SID)).toEqual({ kind: 'entry', entry: ENTRY });
  });
});
