import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import {
  createManualClock,
  createMemorySessionCache,
  createMemorySessionStore,
  type ManualClock,
  type MemorySessionCache,
  type MemorySessionStore,
} from '../testing/memory-ports';
import type { SessionLogger, SessionMetrics } from './ports';
import {
  createSessionService,
  type SessionServiceSettings,
  UnknownSessionRealmError,
} from './session-service';
import type { CreateSessionInput, SessionService } from './types';

const REALM_A = '0199a000-0000-7000-8000-00000000000a';
const REALM_B = '0199a000-0000-7000-8000-00000000000b';
const USER = '0199a000-0000-7000-8000-0000000000aa';

/** `SESSION_COOKIE_TTL` in these tests: one day. */
const COOKIE_TTL_SECONDS = 86_400;
const SECOND = 1000;
const MINUTE = 60 * SECOND;

interface Counted {
  metrics: SessionMetrics;
  counts: Record<string, number>;
}

function countingMetrics(): Counted {
  const counts: Record<string, number> = {};
  const counter = (name: string) => ({
    inc(labels: { result: string }) {
      const key = `${name}:${labels.result}`;
      counts[key] = (counts[key] ?? 0) + 1;
    },
  });
  return {
    counts,
    metrics: {
      cacheLookups: counter('cache'),
      storeReads: counter('store'),
      lastSeenWrites: counter('lastSeen'),
    },
  };
}

let clock: ManualClock;
let store: MemorySessionStore;
let cache: MemorySessionCache;
let counted: Counted;
let warn: Mock<SessionLogger['warn']>;

function serviceWith(
  settings: Partial<SessionServiceSettings> = {},
  ports: { cache?: MemorySessionCache; store?: MemorySessionStore } = {}
): SessionService {
  return createSessionService({
    store: ports.store ?? store,
    cache: ports.cache ?? cache,
    settings: { defaultMaxLifespanSeconds: COOKIE_TTL_SECONDS, ...settings },
    metrics: counted.metrics,
    logger: { warn },
    now: clock.now,
  });
}

function signIn(overrides: Partial<CreateSessionInput> = {}): CreateSessionInput {
  return { realmId: REALM_A, userId: USER, authTime: clock.now(), amr: ['pwd'], ...overrides };
}

beforeEach(() => {
  clock = createManualClock();
  store = createMemorySessionStore(clock);
  cache = createMemorySessionCache(clock);
  counted = countingMetrics();
  warn = vi.fn<SessionLogger['warn']>();
  store.putRealm(REALM_A);
  store.putRealm(REALM_B);
});

describe('create', () => {
  it('always makes a new row and a new id', async () => {
    const service = serviceWith();
    const first = await service.create(signIn());
    const second = await service.create(signIn());

    expect(first.sid).not.toBe(second.sid);
    expect(store.calls.inserts).toBe(2);
    expect(store.row(first.sid)).toMatchObject({ realmId: REALM_A, userId: USER, amr: ['pwd'] });
    expect(store.row(second.sid)).toBeDefined();
  });

  it('writes Postgres first, then the cache', async () => {
    const order: string[] = [];
    const insert = store.insert.bind(store);
    const write = cache.write.bind(cache);
    store.insert = async (row) => {
      order.push('postgres');
      return insert(row);
    };
    cache.write = async (entry, ttl) => {
      order.push('cache');
      return write(entry, ttl);
    };

    const session = await serviceWith().create(signIn());

    expect(order).toEqual(['postgres', 'cache']);
    expect(cache.entry(REALM_A, session.sid)?.record.id).toBe(session.sid);
  });

  it('stores the sign-in request’s columns and nothing else', async () => {
    const input = {
      ...signIn({ assuranceLevel: 'high', ipAddress: '203.0.113.7', userAgent: 'Agent/1.0' }),
      // Volatile per-flow values a caller might still carry: never stored.
      csrfToken: 'csrf',
      consentScopes: { client: ['openid'] },
    };

    const session = await serviceWith().create(input);

    const row = store.row(session.sid);
    expect(Object.keys(row ?? {}).sort()).toEqual(
      [
        'amr',
        'assuranceLevel',
        'authTime',
        'createdAt',
        'expiresAt',
        'id',
        'ipAddress',
        'lastSeenAt',
        'realmId',
        'revokedAt',
        'revokedReason',
        'userAgent',
        'userId',
      ].sort()
    );
    expect(row).toMatchObject({
      assuranceLevel: 'high',
      ipAddress: '203.0.113.7',
      userAgent: 'Agent/1.0',
    });
    // The cache holds neither the address nor the user agent.
    expect(cache.entry(REALM_A, session.sid)?.record).not.toHaveProperty('ipAddress');
    expect(cache.entry(REALM_A, session.sid)?.record).not.toHaveProperty('userAgent');
  });

  it('ends a session of a realm with no lifetimes SESSION_COOKIE_TTL after creation, with no idle limit', async () => {
    const createdAt = clock.now();
    const session = await serviceWith().create(signIn());

    expect(session.expiresAt).toBe(createdAt + COOKIE_TTL_SECONDS * SECOND);
    expect(session.idleExpiresAt).toBeNull();
    expect(store.row(session.sid)?.expiresAt).toBe(createdAt + COOKIE_TTL_SECONDS * SECOND);
  });

  it('takes the absolute end from the realm’s sso_max_lifespan', async () => {
    store.putRealm(REALM_A, { maxLifespanSeconds: 3600, idleTimeoutSeconds: 600 });
    const createdAt = clock.now();

    const session = await serviceWith().create(signIn());

    expect(session.expiresAt).toBe(createdAt + 3600 * SECOND);
    expect(session.idleExpiresAt).toBe(createdAt + 600 * SECOND);
  });

  it('refuses a realm with no row', async () => {
    await expect(
      serviceWith().create(signIn({ realmId: '0199a000-0000-7000-8000-0000000000ff' }))
    ).rejects.toBeInstanceOf(UnknownSessionRealmError);
    expect(store.calls.inserts).toBe(0);
  });

  it('fails when Postgres is down, and caches nothing', async () => {
    store.down = true;
    await expect(serviceWith().create(signIn())).rejects.toThrow('store down');
    expect(cache.calls.writes).toBe(0);
  });

  it('still signs in when the cache is down', async () => {
    cache.down = true;
    const session = await serviceWith().create(signIn());

    expect(store.row(session.sid)).toBeDefined();
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM_A }),
      expect.stringContaining('cache write failed')
    );
  });
});

describe('get', () => {
  it('after a cache miss reads Postgres and fills the cache', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    cache.clear();

    const session = await service.get({ realmId: REALM_A, sid });

    expect(session).toMatchObject({ sid, realmId: REALM_A, userId: USER, amr: ['pwd'] });
    expect(store.calls.reads).toBe(1);
    expect(cache.entry(REALM_A, sid)?.record).toMatchObject({ id: sid, userId: USER });
    expect(counted.counts).toMatchObject({ 'cache:miss': 1, 'store:ok': 1 });

    // The next read is served by the cache.
    await service.get({ realmId: REALM_A, sid });
    expect(store.calls.reads).toBe(1);
    expect(counted.counts['cache:hit']).toBe(1);
  });

  it('fills the cache for 60 seconds by default', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    cache.clear();

    await service.get({ realmId: REALM_A, sid });

    expect(cache.ttlOf(REALM_A, sid)).toBe(60 * SECOND);
  });

  it('never fills the cache past the session’s end', async () => {
    store.putRealm(REALM_A, { maxLifespanSeconds: 90, idleTimeoutSeconds: 600 });
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    clock.advance(70 * SECOND);
    cache.clear();

    await service.get({ realmId: REALM_A, sid });

    expect(cache.ttlOf(REALM_A, sid)).toBe(20 * SECOND);
  });

  it('never fills the cache past the idle end', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 30 });
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    clock.advance(10 * SECOND);
    cache.clear();

    await service.get({ realmId: REALM_A, sid });

    expect(cache.ttlOf(REALM_A, sid)).toBe(20 * SECOND);
  });

  it('serves a cache entry no longer than the cache time, whatever the cache’s own expiry', async () => {
    const service = serviceWith({ cacheTtlSeconds: 10 });
    const { sid } = await service.create(signIn());
    const entry = cache.entry(REALM_A, sid);
    // A cache that kept the entry far longer than it was asked to.
    if (entry === undefined) throw new Error('no entry');
    await cache.write(entry, 3600 * SECOND);
    store.down = true;

    clock.advance(9 * SECOND);
    expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
    clock.advance(1 * SECOND);
    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
  });

  it('answers absent for a revoked session', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    store.update(sid, { revokedAt: clock.now(), revokedReason: 'admin' });
    cache.clear();

    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    expect(cache.entry(REALM_A, sid)).toBeUndefined();
  });

  it('answers absent for an unknown or malformed id, and a malformed one never reaches Postgres', async () => {
    const service = serviceWith();

    expect(
      await service.get({ realmId: REALM_A, sid: '0199a000-0000-7000-8000-000000000999' })
    ).toBeNull();
    expect(store.calls.reads).toBe(1);

    expect(await service.get({ realmId: REALM_A, sid: 'not-a-uuid' })).toBeNull();
    expect(await service.get({ realmId: 'x', sid: '0199a000-0000-7000-8000-000000000999' })).toBe(
      null
    );
    expect(store.calls.reads).toBe(1);
    expect(cache.calls.reads).toBe(1);
  });

  it('reads an upper-case id as the same session', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());

    expect(
      await service.get({ realmId: REALM_A.toUpperCase(), sid: sid.toUpperCase() })
    ).toMatchObject({ sid });
  });

  describe('across realms', () => {
    it('answers absent for a session of realm A read for realm B, from the cache', async () => {
      const service = serviceWith();
      const { sid } = await service.create(signIn());

      expect(await service.get({ realmId: REALM_B, sid })).toBeNull();
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
    });

    it('answers absent for a session of realm A read for realm B, from Postgres', async () => {
      const service = serviceWith();
      const { sid } = await service.create(signIn());
      cache.clear();

      expect(await service.get({ realmId: REALM_B, sid })).toBeNull();
      expect(cache.entry(REALM_B, sid)).toBeUndefined();
    });

    it('does not serve a cache entry that names another realm', async () => {
      const service = serviceWith();
      const { sid } = await service.create(signIn());
      const entry = cache.entry(REALM_A, sid);
      if (entry === undefined) throw new Error('no entry');
      // Realm A's entry, answered for realm B's key.
      cache.read = async () => ({ kind: 'entry', entry });

      expect(await service.get({ realmId: REALM_B, sid })).toBeNull();
      expect(counted.counts).toMatchObject({ 'cache:miss': 1, 'store:ok': 1 });
      expect(counted.counts['cache:hit']).toBeUndefined();
    });
  });

  describe('lifetimes from the realm row', () => {
    it('enforces the absolute end of sso_max_lifespan', async () => {
      store.putRealm(REALM_A, { maxLifespanSeconds: 3600 });
      const service = serviceWith();
      const { sid } = await service.create(signIn());

      clock.advance(3600 * SECOND - 1);
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
      clock.advance(1);
      expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
      cache.clear();
      expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    });

    it('enforces the idle limit of sso_idle_timeout, judged from the stored last-seen time', async () => {
      store.putRealm(REALM_A, { idleTimeoutSeconds: 600 });
      const service = serviceWith();
      const { sid } = await service.create(signIn());

      clock.advance(600 * SECOND - 1);
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
      // That read wrote last_seen_at, which restarts the idle time.
      clock.advance(600 * SECOND - 1);
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
      clock.advance(600 * SECOND);
      expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    });

    it('keeps a session used by another node alive, though its cached last-seen time says idle', async () => {
      store.putRealm(REALM_A, { idleTimeoutSeconds: 600 });
      const service = serviceWith({ cacheTtlSeconds: 3600 });
      const { sid } = await service.create(signIn());
      // Another node used the session; this node's entry still shows creation.
      clock.advance(590 * SECOND);
      store.update(sid, { lastSeenAt: clock.now() });

      clock.advance(20 * SECOND);
      const session = await service.get({ realmId: REALM_A, sid });

      expect(session).not.toBeNull();
      expect(store.calls.reads).toBe(1);
    });

    it('uses SESSION_COOKIE_TTL for a realm with neither, and no idle limit', async () => {
      const service = serviceWith();
      const { sid } = await service.create(signIn());

      // Unused for 23 hours: no idle limit ends it.
      clock.advance(23 * 3600 * SECOND);
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
      clock.advance(3600 * SECOND - 1);
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
      clock.advance(1);
      expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    });

    it('applies a realm’s shortened maximum lifespan to live sessions, within the cache time', async () => {
      const service = serviceWith();
      const { sid } = await service.create(signIn());
      clock.advance(2 * 3600 * SECOND);
      store.putRealm(REALM_A, { maxLifespanSeconds: 3600 });

      // The entry still holds the old lifetimes until it lapses.
      cache.clear();
      expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    });

    it('never extends a session past the expires_at it was given', async () => {
      const service = serviceWith();
      const createdAt = clock.now();
      const { sid } = await service.create(signIn());
      store.putRealm(REALM_A, { maxLifespanSeconds: 10 * COOKIE_TTL_SECONDS });
      cache.clear();

      const session = await service.get({ realmId: REALM_A, sid });
      expect(session?.expiresAt).toBe(createdAt + COOKIE_TTL_SECONDS * SECOND);
    });

    it('answers absent past the stored expires_at', async () => {
      const service = serviceWith();
      const { sid } = await service.create(signIn());
      store.update(sid, { expiresAt: clock.now() + MINUTE });
      cache.clear();

      clock.advance(MINUTE);
      expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    });
  });
});

describe('the last-seen write throttle', () => {
  it('writes last_seen_at once for 100 reads inside one interval', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    clock.advance(MINUTE);

    for (let i = 0; i < 100; i++) {
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
      clock.advance(500);
    }

    expect(store.calls.touchWrites).toBe(1);
    expect(store.calls.touchAttempts).toBe(1);
    expect(counted.counts['lastSeen:written']).toBe(1);
  });

  it('writes last_seen_at once for 100 concurrent reads', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    clock.advance(MINUTE);

    const reads = await Promise.all(
      Array.from({ length: 100 }, () => service.get({ realmId: REALM_A, sid }))
    );

    expect(reads.every((session) => session?.sid === sid)).toBe(true);
    expect(store.calls.touchWrites).toBe(1);
    expect(store.calls.touchAttempts).toBe(1);
  });

  it('writes last_seen_at once for 100 reads with the cache down', async () => {
    cache.down = true;
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    clock.advance(MINUTE);

    for (let i = 0; i < 100; i++) {
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
    }

    expect(store.calls.touchWrites).toBe(1);
  });

  it('writes nothing within the first interval of a new session', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());

    for (let i = 0; i < 59; i++) {
      await service.get({ realmId: REALM_A, sid });
      clock.advance(SECOND);
    }

    expect(store.calls.touchAttempts).toBe(0);
  });

  it('writes again once the interval has passed', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());

    clock.advance(MINUTE);
    await service.get({ realmId: REALM_A, sid });
    const firstWrite = clock.now();
    clock.advance(MINUTE - 1);
    await service.get({ realmId: REALM_A, sid });
    clock.advance(1);
    await service.get({ realmId: REALM_A, sid });

    expect(store.calls.touchWrites).toBe(2);
    expect(store.row(sid)?.lastSeenAt).toBe(firstWrite + MINUTE);
  });

  it('follows SESSION_LAST_SEEN_INTERVAL', async () => {
    const service = serviceWith({ lastSeenIntervalSeconds: 300 });
    const { sid } = await service.create(signIn());

    for (let i = 0; i < 10; i++) {
      clock.advance(MINUTE);
      await service.get({ realmId: REALM_A, sid });
    }

    expect(store.calls.touchWrites).toBe(2);
  });

  it('writes at least twice per idle limit, so a session in use never idles out', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 60 });
    const service = serviceWith({ lastSeenIntervalSeconds: 300 });
    const { sid } = await service.create(signIn());

    for (let i = 0; i < 20; i++) {
      clock.advance(25 * SECOND);
      expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
    }
  });

  it('reads Postgres when another node wrote first, and does not write', async () => {
    // An interval shorter than the cache time, so the write falls due while
    // the cache entry is still served.
    const service = serviceWith({ lastSeenIntervalSeconds: 30 });
    const { sid } = await service.create(signIn());
    clock.advance(30 * SECOND);
    // Another node's write, which this node's cache entry does not show.
    store.update(sid, { lastSeenAt: clock.now() - SECOND });

    const session = await service.get({ realmId: REALM_A, sid });

    expect(session?.lastSeenAt).toBe(clock.now() - SECOND);
    expect(store.calls.touchAttempts).toBe(1);
    expect(store.calls.touchWrites).toBe(0);
    expect(counted.counts['lastSeen:skipped']).toBe(1);
    expect(cache.entry(REALM_A, sid)?.record.lastSeenAt).toBe(clock.now() - SECOND);
  });

  it('finds a revocation when the write is skipped', async () => {
    const service = serviceWith({ lastSeenIntervalSeconds: 30 });
    const { sid } = await service.create(signIn());
    clock.advance(30 * SECOND);
    // Revoked behind this node's back, with no tombstone.
    store.update(sid, { revokedAt: clock.now(), revokedReason: 'admin' });

    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
  });

  it('keeps the entry’s freshness after a write, so the realm row is read again in time', async () => {
    const service = serviceWith({ lastSeenIntervalSeconds: 30 });
    const createdAt = clock.now();
    const { sid } = await service.create(signIn());
    clock.advance(30 * SECOND);

    await service.get({ realmId: REALM_A, sid });

    expect(store.calls.touchWrites).toBe(1);
    expect(cache.entry(REALM_A, sid)).toMatchObject({
      record: { lastSeenAt: createdAt + 30 * SECOND },
      freshUntil: createdAt + MINUTE,
    });
  });
});

describe('with the cache down', () => {
  it('reads Postgres', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    cache.down = true;

    expect(await service.get({ realmId: REALM_A, sid })).toMatchObject({ sid });
    expect(counted.counts).toMatchObject({ 'cache:error': 1, 'store:ok': 1 });
    expect(counted.counts['cache:miss']).toBeUndefined();
  });

  it('works after the cache lost its data', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    cache.clear();

    expect(await service.get({ realmId: REALM_A, sid })).toMatchObject({ sid });
  });

  it('still ends a session, in Postgres', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    cache.down = true;

    expect(await service.revoke({ realmId: REALM_A, sid, reason: 'sign_out' })).toMatchObject({
      id: sid,
      revokedReason: 'sign_out',
    });
    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    expect(warn).toHaveBeenCalledWith(
      expect.anything(),
      expect.stringContaining('tombstone write failed')
    );
  });
});

describe('with Postgres down', () => {
  it('answers absent for a session the cache does not hold, without throwing', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    cache.clear();
    store.down = true;

    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    expect(counted.counts['store:error']).toBe(1);
  });

  it('answers absent once the last-seen time needs a write, though the cache holds it', async () => {
    const service = serviceWith({ lastSeenIntervalSeconds: 30 });
    const { sid } = await service.create(signIn());
    store.down = true;

    clock.advance(30 * SECOND);
    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    expect(counted.counts['lastSeen:error']).toBe(1);
  });

  it('serves a cached session for no longer than the cache time', async () => {
    const service = serviceWith({ lastSeenIntervalSeconds: 3600 });
    const { sid } = await service.create(signIn());
    store.down = true;

    clock.advance(MINUTE - 1);
    expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();
    clock.advance(1);
    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
  });

  it('refuses to end a session rather than pretend it did', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    store.down = true;

    await expect(service.revoke({ realmId: REALM_A, sid, reason: 'sign_out' })).rejects.toThrow(
      'store down'
    );
    expect(cache.calls.tombstones).toBe(0);
  });
});

describe('revoke', () => {
  it('updates Postgres, replaces the cache entry with a short tombstone, and the next read is absent', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());

    const ended = await service.revoke({ realmId: REALM_A, sid, reason: 'sign_out' });

    expect(ended).toMatchObject({ id: sid, revokedAt: clock.now(), revokedReason: 'sign_out' });
    expect(store.row(sid)?.revokedReason).toBe('sign_out');
    expect(cache.entry(REALM_A, sid)).toBeUndefined();
    expect(await cache.read(REALM_A, sid)).toEqual({ kind: 'revoked' });
    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    expect(counted.counts['cache:revoked']).toBe(1);

    // The tombstone lasts the cache time.
    clock.advance(MINUTE);
    expect(await cache.read(REALM_A, sid)).toEqual({ kind: 'empty' });
    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
  });

  it('is not undone by an entry filled from a read that began before it', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());
    const stale = cache.entry(REALM_A, sid);
    if (stale === undefined) throw new Error('no entry');

    await service.revoke({ realmId: REALM_A, sid, reason: 'sign_out' });
    await cache.write(stale, stale.freshUntil - clock.now());

    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
  });

  it('is seen by another node with its own cache within the cache time', async () => {
    const service = serviceWith();
    const otherCache = createMemorySessionCache(clock);
    const otherNode = serviceWith({}, { cache: otherCache });
    const { sid } = await service.create(signIn());
    expect(await otherNode.get({ realmId: REALM_A, sid })).not.toBeNull();

    await service.revoke({ realmId: REALM_A, sid, reason: 'sign_out_everywhere' });

    expect(await service.get({ realmId: REALM_A, sid })).toBeNull();
    clock.advance(MINUTE);
    expect(await otherNode.get({ realmId: REALM_A, sid })).toBeNull();
  });

  it('changes nothing the second time, and does not end another realm’s session', async () => {
    const service = serviceWith();
    const { sid } = await service.create(signIn());

    expect(await service.revoke({ realmId: REALM_B, sid, reason: 'admin' })).toBeNull();
    expect(await service.get({ realmId: REALM_A, sid })).not.toBeNull();

    expect(await service.revoke({ realmId: REALM_A, sid, reason: 'admin' })).not.toBeNull();
    expect(await service.revoke({ realmId: REALM_A, sid, reason: 'reset' })).toBeNull();
    expect(store.row(sid)?.revokedReason).toBe('admin');
  });

  it('ignores a malformed id', async () => {
    expect(await serviceWith().revoke({ realmId: REALM_A, sid: 'x', reason: 'admin' })).toBeNull();
    expect(store.calls.revokes).toBe(0);
  });
});

describe('settings', () => {
  it.each([
    ['defaultMaxLifespanSeconds', { defaultMaxLifespanSeconds: 0 }],
    ['lastSeenIntervalSeconds', { lastSeenIntervalSeconds: -1 }],
    ['cacheTtlSeconds', { cacheTtlSeconds: Number.NaN }],
  ])('refuses a %s that is not a positive number', (name, settings) => {
    expect(() => serviceWith(settings)).toThrow(name);
  });
});
