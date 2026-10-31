import { beforeEach, describe, expect, it, type Mock, vi } from 'vitest';

import {
  createManualClock,
  createMemorySessionCache,
  createMemorySessionStore,
  type ManualClock,
  type MemorySessionCache,
  type MemorySessionStore,
} from '../testing/memory-ports';
import type { SessionLogger } from './ports';
import { InvalidSessionCursorError } from './session-cursor';
import {
  createSessionService,
  MAX_SESSION_PAGE_LIMIT,
  SESSION_CLOCK_SKEW_ALLOWANCE_MS,
} from './session-service';
import type {
  CreateSessionInput,
  SessionActor,
  SessionClientRecord,
  SessionsEndedNotice,
  SessionService,
} from './types';

/**
 * The session lists and revocations of the service (ADR-019 Decisions 3 and 4,
 * issue #550), on the in-memory ports: list a user's or a client's sessions,
 * end one, a user's or a realm's, mark the lapsed ones, purge old rows, and
 * tell the `onSessionsEnded` listeners.
 */

const REALM_A = '0199a000-0000-7000-8000-00000000000a';
const REALM_B = '0199a000-0000-7000-8000-00000000000b';
const ALICE = '0199a000-0000-7000-8000-0000000000aa';
const BOB = '0199a000-0000-7000-8000-0000000000bb';
const APP: Omit<SessionClientRecord, 'firstSeenAt'> = {
  oauthClientId: '0199a000-0000-7000-8000-0000000000c1',
  clientId: 'app',
  name: 'App',
};
const PORTAL: Omit<SessionClientRecord, 'firstSeenAt'> = {
  oauthClientId: '0199a000-0000-7000-8000-0000000000c2',
  clientId: 'portal',
  name: 'Portal',
};
const ALICE_ACTOR: SessionActor = { type: 'user', id: ALICE };
const ADMIN_ACTOR: SessionActor = { type: 'user', id: BOB };

const SECOND = 1000;
const MINUTE = 60 * SECOND;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
/** `SESSION_COOKIE_TTL` in these tests: one day. */
const COOKIE_TTL_SECONDS = 86_400;

let clock: ManualClock;
let store: MemorySessionStore;
let cache: MemorySessionCache;
let warn: Mock<SessionLogger['warn']>;
let service: SessionService;
let notices: SessionsEndedNotice[];

function serviceWith(ports: { cache?: MemorySessionCache } = {}): SessionService {
  return createSessionService({
    store,
    cache: ports.cache ?? cache,
    settings: { defaultMaxLifespanSeconds: COOKIE_TTL_SECONDS },
    logger: { warn },
    now: clock.now,
  });
}

function signIn(overrides: Partial<CreateSessionInput> = {}): CreateSessionInput {
  return {
    realmId: REALM_A,
    userId: ALICE,
    authTime: clock.now(),
    amr: ['pwd'],
    ipAddress: '192.0.2.10',
    userAgent: 'Browser/1.0',
    ...overrides,
  };
}

/** Sign in, then move the clock on, so each session has its own creation time. */
async function signInAt(overrides: Partial<CreateSessionInput> = {}): Promise<string> {
  const { sid } = await service.create(signIn(overrides));
  clock.advance(SECOND);
  return sid;
}

/** The sids each notice carried, in order. */
function noticedSids(): string[] {
  return notices.flatMap((notice) => notice.sessions.map((ended) => ended.session.id));
}

beforeEach(() => {
  clock = createManualClock();
  store = createMemorySessionStore(clock);
  cache = createMemorySessionCache(clock);
  warn = vi.fn<SessionLogger['warn']>();
  store.putRealm(REALM_A);
  store.putRealm(REALM_B);
  service = serviceWith();
  notices = [];
  service.onSessionsEnded((notice) => {
    notices.push(notice);
  });
});

describe('listForUser', () => {
  it('lists the user’s sessions newest first, with their clients, address, user agent, auth_time, last_seen_at and state', async () => {
    const older = await signInAt();
    const newer = await signInAt({ userAgent: 'Phone/2.0' });
    store.recordClient(older, { ...APP, firstSeenAt: clock.now() - 500 });
    store.recordClient(older, { ...PORTAL, firstSeenAt: clock.now() - 100 });

    const page = await service.listForUser({ realmId: REALM_A, userId: ALICE });

    expect(page.nextCursor).toBeNull();
    expect(page.items.map((item) => item.sid)).toEqual([newer, older]);
    expect(page.items[1]).toMatchObject({
      sid: older,
      realmId: REALM_A,
      userId: ALICE,
      authTime: expect.any(Number),
      amr: ['pwd'],
      ipAddress: '192.0.2.10',
      userAgent: 'Browser/1.0',
      lastSeenAt: expect.any(Number),
      expiresAt: expect.any(Number),
      idleExpiresAt: null,
      state: 'live',
      revokedAt: null,
      revokedReason: null,
    });
    expect(page.items[1].clients.map((client) => client.clientId)).toEqual(['app', 'portal']);
    expect(page.items[0]).toMatchObject({ userAgent: 'Phone/2.0', clients: [] });
  });

  it('says which sessions are live, idle, expired or revoked', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 600 });
    const revoked = await signInAt();
    const expired = await signInAt();
    const idle = await signInAt();
    const live = await signInAt();
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid: revoked,
      reason: 'admin',
      actor: ADMIN_ACTOR,
    });
    store.update(expired, { expiresAt: clock.now() - 1 });
    store.update(idle, { lastSeenAt: clock.now() - 601 * SECOND });

    const { items } = await service.listForUser({ realmId: REALM_A, userId: ALICE });

    expect(Object.fromEntries(items.map((item) => [item.sid, item.state]))).toEqual({
      [revoked]: 'revoked',
      [expired]: 'expired',
      [idle]: 'idle',
      [live]: 'live',
    });
    expect(items.find((item) => item.sid === revoked)?.revokedReason).toBe('admin');
  });

  it('keeps the idle or expired state of a session the purge job marked', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 600 });
    const idle = await signInAt();
    clock.advance(11 * MINUTE);
    await service.endLapsed();

    const [item] = (await service.listForUser({ realmId: REALM_A, userId: ALICE })).items;

    expect(item).toMatchObject({ sid: idle, state: 'idle', revokedReason: 'idle' });
  });

  it('pages through the list with the cursor, and reads no further than the last page', async () => {
    const sids: string[] = [];
    for (let i = 0; i < 5; i++) sids.push(await signInAt());
    const newestFirst = [...sids].reverse();

    const first = await service.listForUser({
      realmId: REALM_A,
      userId: ALICE,
      page: { limit: 2 },
    });
    const second = await service.listForUser({
      realmId: REALM_A,
      userId: ALICE,
      page: { limit: 2, cursor: first.nextCursor ?? '' },
    });
    const third = await service.listForUser({
      realmId: REALM_A,
      userId: ALICE,
      page: { limit: 2, cursor: second.nextCursor ?? '' },
    });

    expect([...first.items, ...second.items, ...third.items].map((item) => item.sid)).toEqual(
      newestFirst
    );
    expect(first.nextCursor).not.toBeNull();
    expect(third.nextCursor).toBeNull();
  });

  it('breaks ties between sessions created in the same millisecond by id', async () => {
    const a = (await service.create(signIn())).sid;
    const b = (await service.create(signIn())).sid;
    const expected = [a, b].sort().reverse();

    const first = await service.listForUser({
      realmId: REALM_A,
      userId: ALICE,
      page: { limit: 1 },
    });
    const second = await service.listForUser({
      realmId: REALM_A,
      userId: ALICE,
      page: { limit: 1, cursor: first.nextCursor ?? '' },
    });

    expect([first.items[0].sid, second.items[0].sid]).toEqual(expected);
    expect(second.nextCursor).toBeNull();
  });

  it('never lists another realm’s sessions', async () => {
    await signInAt({ realmId: REALM_B });
    const mine = await signInAt();

    expect(
      (await service.listForUser({ realmId: REALM_A, userId: ALICE })).items.map((i) => i.sid)
    ).toEqual([mine]);
    expect((await service.listForUser({ realmId: REALM_B, userId: BOB })).items).toEqual([]);
  });

  it('refuses a cursor of another list, and one that does not parse', async () => {
    await signInAt();
    await signInAt();
    await signInAt({ userId: BOB });
    store.recordClient((await service.create(signIn())).sid, APP);
    const cursor = (
      await service.listForUser({ realmId: REALM_A, userId: ALICE, page: { limit: 1 } })
    ).nextCursor;
    if (cursor === null) throw new Error('no cursor');

    for (const input of [
      { realmId: REALM_A, userId: BOB },
      { realmId: REALM_B, userId: ALICE },
    ]) {
      await expect(service.listForUser({ ...input, page: { cursor } })).rejects.toBeInstanceOf(
        InvalidSessionCursorError
      );
    }
    await expect(
      service.listForClient({
        realmId: REALM_A,
        oauthClientId: APP.oauthClientId,
        page: { cursor },
      })
    ).rejects.toBeInstanceOf(InvalidSessionCursorError);
    for (const bad of ['not a cursor', 'e30', 'x'.repeat(513), `${cursor}A`]) {
      await expect(
        service.listForUser({ realmId: REALM_A, userId: ALICE, page: { cursor: bad } })
      ).rejects.toBeInstanceOf(InvalidSessionCursorError);
    }
  });

  it('takes 50 sessions a page by default and refuses a limit out of range', async () => {
    for (let i = 0; i < 51; i++) await signInAt();

    const page = await service.listForUser({ realmId: REALM_A, userId: ALICE });

    expect(page.items).toHaveLength(50);
    expect(page.nextCursor).not.toBeNull();
    for (const limit of [0, -1, 1.5, MAX_SESSION_PAGE_LIMIT + 1]) {
      await expect(
        service.listForUser({ realmId: REALM_A, userId: ALICE, page: { limit } })
      ).rejects.toThrow(RangeError);
    }
  });

  it('lists nothing for a malformed id, without asking Postgres', async () => {
    const reads = store.calls.reads;

    expect(await service.listForUser({ realmId: REALM_A, userId: 'nobody' })).toEqual({
      items: [],
      nextCursor: null,
    });
    expect(await service.listForUser({ realmId: 'nowhere', userId: ALICE })).toEqual({
      items: [],
      nextCursor: null,
    });
    expect(store.calls.reads).toBe(reads);
  });
});

describe('listForClient', () => {
  it('lists the realm’s sessions that served the client, newest first, each with all its clients', async () => {
    const both = await signInAt();
    const appOnly = await signInAt({ userId: BOB });
    const portalOnly = await signInAt();
    store.recordClient(both, APP);
    store.recordClient(both, PORTAL);
    store.recordClient(appOnly, APP);
    store.recordClient(portalOnly, PORTAL);

    const { items } = await service.listForClient({
      realmId: REALM_A,
      oauthClientId: APP.oauthClientId,
    });

    expect(items.map((item) => item.sid)).toEqual([appOnly, both]);
    expect(items[1].clients.map((client) => client.clientId)).toEqual(['app', 'portal']);
    expect(
      (await service.listForClient({ realmId: REALM_B, oauthClientId: APP.oauthClientId })).items
    ).toEqual([]);
  });

  it('shows no client of a revoked session, even one whose registry rows were left behind', async () => {
    const sid = await signInAt();
    store.recordClient(sid, APP);
    // As a previous release revokes during a rolling upgrade: the row only.
    store.update(sid, { revokedAt: clock.now(), revokedReason: 'sign_out' });

    expect(
      (await service.listForClient({ realmId: REALM_A, oauthClientId: APP.oauthClientId })).items
    ).toEqual([]);
    const [item] = (await service.listForUser({ realmId: REALM_A, userId: ALICE })).items;
    expect(item).toMatchObject({ sid, state: 'revoked', clients: [] });
  });

  it('no longer lists a session once it ended', async () => {
    const sid = await signInAt();
    store.recordClient(sid, APP);
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid,
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });

    expect(
      (await service.listForClient({ realmId: REALM_A, oauthClientId: APP.oauthClientId })).items
    ).toEqual([]);
  });
});

describe('revoke', () => {
  it('ends one session and returns it with its clients, once', async () => {
    const sid = await signInAt();
    const other = await signInAt();
    store.recordClient(sid, APP);

    const result = await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid,
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });

    expect(result).toMatchObject({
      outcome: 'ended',
      session: { id: sid, revokedReason: 'sign_out', revokedAt: clock.now() },
      clients: [expect.objectContaining({ clientId: 'app' })],
    });
    expect(store.clientsOf(sid)).toEqual([]);
    expect(await service.get({ realmId: REALM_A, sid: other })).not.toBeNull();
    expect(notices).toEqual([
      {
        realmId: REALM_A,
        reason: 'sign_out',
        actor: ALICE_ACTOR,
        sessions: [
          expect.objectContaining({
            session: expect.objectContaining({ id: sid }),
            clients: [expect.objectContaining({ clientId: 'app' })],
          }),
        ],
      },
    ]);
  });

  it('reports a second call as already ended, and tells no listener again', async () => {
    const sid = await signInAt();
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid,
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });
    const row = store.row(sid);

    const again = await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid,
      reason: 'admin',
      actor: ADMIN_ACTOR,
    });

    expect(again).toEqual({ outcome: 'already_ended', session: row });
    expect(store.row(sid)).toEqual(row);
    expect(notices).toHaveLength(1);
  });

  it('ends only the named owner’s session: another user’s is not found, and untouched', async () => {
    const bobs = await signInAt({ userId: BOB });
    store.recordClient(bobs, APP);

    expect(
      await service.revoke({
        realmId: REALM_A,
        userId: ALICE,
        sid: bobs,
        reason: 'sign_out',
        actor: ALICE_ACTOR,
      })
    ).toEqual({ outcome: 'not_found' });
    expect(store.row(bobs)?.revokedAt).toBeNull();
    expect(store.clientsOf(bobs)).toHaveLength(1);
    expect(cache.calls.tombstones).toBe(0);
    expect(await service.get({ realmId: REALM_A, sid: bobs })).not.toBeNull();
    expect(notices).toEqual([]);
  });

  it('answers another user’s ended session as not found, without its record', async () => {
    const bobs = await signInAt({ userId: BOB });
    await service.revoke({
      realmId: REALM_A,
      userId: BOB,
      sid: bobs,
      reason: 'sign_out',
      actor: { type: 'user', id: BOB },
    });

    expect(
      await service.revoke({
        realmId: REALM_A,
        userId: ALICE,
        sid: bobs,
        reason: 'admin',
        actor: ALICE_ACTOR,
      })
    ).toEqual({ outcome: 'not_found' });
    expect(store.row(bobs)?.revokedReason).toBe('sign_out');
  });

  it('refuses a user actor that names no owner, and lets the system end any session', async () => {
    const sid = await signInAt();

    await expect(
      service.revoke({ realmId: REALM_A, sid, reason: 'sign_out', actor: ALICE_ACTOR })
    ).rejects.toThrow(RangeError);
    expect(store.calls.revokes).toBe(0);

    expect(
      await service.revoke({ realmId: REALM_A, sid, reason: 'admin', actor: { type: 'system' } })
    ).toMatchObject({ outcome: 'ended', session: { id: sid, userId: ALICE } });
  });

  it('refuses an unknown reason or a malformed actor before Postgres sees anything', async () => {
    const sid = await signInAt();
    const bad = [
      { reason: 'bored', actor: ALICE_ACTOR },
      { reason: 'sign_out', actor: { type: 'robot' } },
      { reason: 'sign_out', actor: { type: 'user', id: '' } },
      { reason: 'sign_out', actor: { type: 'user' } },
      { reason: 'sign_out', actor: { type: 'client', id: 'x'.repeat(256) } },
      { reason: 'sign_out', actor: { type: 'system', id: 'cron' } },
      { reason: 'sign_out', actor: undefined },
    ];
    for (const input of bad) {
      await expect(
        service.revoke({ realmId: REALM_A, sid, ...input } as unknown as Parameters<
          SessionService['revoke']
        >[0])
      ).rejects.toThrow(RangeError);
    }
    expect(store.calls.revokes).toBe(0);
  });
});

describe('revokeAllForUser', () => {
  it('ends every session of the user but the one excepted', async () => {
    const a = await signInAt();
    const kept = await signInAt();
    const b = await signInAt();
    const bobs = await signInAt({ userId: BOB });
    const elsewhere = await signInAt({ realmId: REALM_B });
    store.recordClient(a, APP);

    const { sessions } = await service.revokeAllForUser({
      realmId: REALM_A,
      userId: ALICE,
      exceptSid: kept.toUpperCase(),
      reason: 'sign_out_everywhere',
      actor: ALICE_ACTOR,
    });

    expect(sessions.map((ended) => ended.session.id)).toEqual([a, b].sort());
    expect(sessions.find((ended) => ended.session.id === a)?.clients).toEqual([
      expect.objectContaining({ clientId: 'app' }),
    ]);
    for (const survivor of [kept, bobs]) {
      expect(await service.get({ realmId: REALM_A, sid: survivor })).not.toBeNull();
    }
    expect(await service.get({ realmId: REALM_B, sid: elsewhere })).not.toBeNull();
    expect(await service.get({ realmId: REALM_A, sid: a })).toBeNull();
    expect(await cache.read(REALM_A, b)).toEqual({ kind: 'revoked' });
  });

  it('with createdBefore ends only the older sessions, as a password reset does', async () => {
    const older = await signInAt();
    const resetAt = clock.now();
    const newer = await signInAt();

    const { sessions } = await service.revokeAllForUser({
      realmId: REALM_A,
      userId: ALICE,
      createdBefore: resetAt,
      reason: 'reset',
      actor: ALICE_ACTOR,
    });

    expect(sessions.map((ended) => ended.session.id)).toEqual([older]);
    expect(await service.get({ realmId: REALM_A, sid: newer })).not.toBeNull();
  });

  it('tells the listeners once, with the reason, the actor and each session’s clients', async () => {
    const a = await signInAt();
    const b = await signInAt();
    store.recordClient(b, PORTAL);

    await service.revokeAllForUser({
      realmId: REALM_A,
      userId: ALICE,
      reason: 'sign_out_everywhere',
      actor: ALICE_ACTOR,
    });
    await service.revokeAllForUser({
      realmId: REALM_A,
      userId: ALICE,
      reason: 'sign_out_everywhere',
      actor: ALICE_ACTOR,
    });

    expect(notices).toHaveLength(1);
    expect(notices[0]).toMatchObject({ realmId: REALM_A, reason: 'sign_out_everywhere' });
    expect(notices[0].actor).toEqual(ALICE_ACTOR);
    expect(noticedSids()).toEqual([a, b].sort());
    expect(
      notices[0].sessions.find((ended) => ended.session.id === b)?.clients.map((c) => c.clientId)
    ).toEqual(['portal']);
  });

  it('refuses a malformed exceptSid rather than end the session meant to stay', async () => {
    await signInAt();

    await expect(
      service.revokeAllForUser({
        realmId: REALM_A,
        userId: ALICE,
        exceptSid: 'current',
        reason: 'sign_out_everywhere',
        actor: ALICE_ACTOR,
      })
    ).rejects.toThrow(RangeError);
    expect(store.calls.revocationBatches).toBe(0);
  });

  it('still ends the sessions when the cache is down, with one warning', async () => {
    await signInAt();
    await signInAt();
    cache.down = true;

    const { sessions } = await service.revokeAllForUser({
      realmId: REALM_A,
      userId: ALICE,
      reason: 'sign_out_everywhere',
      actor: ALICE_ACTOR,
    });

    expect(sessions).toHaveLength(2);
    expect(warn).toHaveBeenCalledTimes(1);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ sessions: 2 }),
      expect.stringContaining('tombstone write failed')
    );
    expect(notices).toHaveLength(1);
  });
});

describe('revokeAllForRealm', () => {
  it('ends the realm’s sessions in batches, each session once, and leaves other realms', async () => {
    const sids: string[] = [];
    for (let i = 0; i < 7; i++) sids.push(await signInAt({ userId: i % 2 === 0 ? ALICE : BOB }));
    const elsewhere = await signInAt({ realmId: REALM_B });

    const result = await service.revokeAllForRealm({
      realmId: REALM_A,
      reason: 'key_retired',
      actor: { type: 'operator_cli', id: 'root' },
      batchSize: 3,
    });

    expect(result).toEqual({ ended: 7, batches: 3 });
    expect(store.calls.revocationBatches).toBe(3);
    expect(notices.map((notice) => notice.sessions.length)).toEqual([3, 3, 1]);
    expect(noticedSids()).toEqual([...sids].sort());
    expect(new Set(noticedSids()).size).toBe(7);
    for (const sid of sids) expect(store.row(sid)?.revokedReason).toBe('key_retired');
    expect(await service.get({ realmId: REALM_B, sid: elsewhere })).not.toBeNull();
  });

  it('with activeSince ends only the sessions used since then', async () => {
    const stale = await signInAt();
    clock.advance(HOUR);
    const since = clock.now();
    const recent = await signInAt();

    expect(
      await service.revokeAllForRealm({
        realmId: REALM_A,
        activeSince: since,
        reason: 'admin',
        actor: ADMIN_ACTOR,
      })
    ).toEqual({ ended: 1, batches: 1 });
    expect(store.row(recent)?.revokedAt).not.toBeNull();
    expect(store.row(stale)?.revokedAt).toBeNull();
  });

  it('counts a session stored as seen up to one write interval before activeSince as used since then', async () => {
    const since = clock.now() + HOUR;
    const lagging = await signInAt();
    const stale = await signInAt();
    // Last-seen writes come once a minute (SESSION_LAST_SEEN_INTERVAL's
    // default): one stored 30 s before `since` may have been used at it.
    store.update(lagging, { lastSeenAt: since - 30 * SECOND });
    store.update(stale, { lastSeenAt: since - 61 * SECOND });
    clock.set(since + MINUTE);

    await service.revokeAllForRealm({
      realmId: REALM_A,
      activeSince: since,
      reason: 'admin',
      actor: ADMIN_ACTOR,
    });

    expect(store.row(lagging)?.revokedAt).not.toBeNull();
    expect(store.row(stale)?.revokedAt).toBeNull();
  });

  it('refuses a batch larger than one transaction may hold', async () => {
    for (const batchSize of [0, 5001, 2.5]) {
      await expect(
        service.revokeAllForRealm({
          realmId: REALM_A,
          reason: 'admin',
          actor: ADMIN_ACTOR,
          batchSize,
        })
      ).rejects.toThrow(RangeError);
    }
    await expect(service.purge({ endedBefore: clock.now(), batchSize: 10_000 })).rejects.toThrow(
      RangeError
    );
  });

  it('leaves a session created after the call began, past the skew allowance', async () => {
    for (let i = 0; i < 4; i++) await signInAt();
    let signedInDuring: string | undefined;
    service.onSessionsEnded(async () => {
      if (signedInDuring !== undefined) return;
      clock.advance(SESSION_CLOCK_SKEW_ALLOWANCE_MS + 1);
      signedInDuring = (await service.create(signIn())).sid;
    });

    const result = await service.revokeAllForRealm({
      realmId: REALM_A,
      reason: 'key_retired',
      actor: { type: 'system' },
      batchSize: 2,
    });

    expect(result.ended).toBe(4);
    expect(signedInDuring).toBeDefined();
    expect(await service.get({ realmId: REALM_A, sid: signedInDuring ?? '' })).not.toBeNull();
  });

  it('ends a session another node stamped up to the skew allowance ahead of this one', async () => {
    const before = await signInAt();
    // Created before the call on a node whose clock runs ahead: its
    // created_at is later than this node's clock when the call begins.
    const { sid: ahead } = await service.create(signIn());
    store.update(ahead, { createdAt: clock.now() + SESSION_CLOCK_SKEW_ALLOWANCE_MS });
    const { sid: tooFar } = await service.create(signIn());
    store.update(tooFar, { createdAt: clock.now() + SESSION_CLOCK_SKEW_ALLOWANCE_MS + 1 });

    expect(
      await service.revokeAllForRealm({ realmId: REALM_A, reason: 'admin', actor: ADMIN_ACTOR })
    ).toEqual({ ended: 2, batches: 1 });
    expect(store.row(before)?.revokedAt).not.toBeNull();
    expect(store.row(ahead)?.revokedAt).not.toBeNull();
    expect(store.row(tooFar)?.revokedAt).toBeNull();
  });

  it('ends nothing more when repeated', async () => {
    await signInAt();
    await service.revokeAllForRealm({ realmId: REALM_A, reason: 'admin', actor: ADMIN_ACTOR });

    expect(
      await service.revokeAllForRealm({ realmId: REALM_A, reason: 'admin', actor: ADMIN_ACTOR })
    ).toEqual({ ended: 0, batches: 0 });
    expect(notices).toHaveLength(1);
  });
});

describe('endLapsed', () => {
  it('marks the sessions past an end as idle or expired, as the system, and leaves live ones', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 600 });
    const idleA = await signInAt();
    const expiredB = await signInAt({ realmId: REALM_B, userId: BOB });
    const liveA = await signInAt();
    store.update(expiredB, { expiresAt: clock.now() + 5 * MINUTE });
    store.recordClient(idleA, APP);
    clock.advance(10 * MINUTE);
    // Used just now: live.
    store.update(liveA, { lastSeenAt: clock.now() });

    expect(await service.endLapsed()).toEqual({ ended: 2 });

    // Marked at the time of the run: retention counts from it.
    expect(store.row(idleA)).toMatchObject({ revokedReason: 'idle', revokedAt: clock.now() });
    expect(store.row(expiredB)).toMatchObject({
      revokedReason: 'expired',
      revokedAt: clock.now(),
    });
    expect(store.row(liveA)?.revokedAt).toBeNull();
    expect(store.clientsOf(idleA)).toEqual([]);
    expect(
      notices.map((notice) => [notice.realmId, notice.reason, notice.actor.type]).sort()
    ).toEqual([
      [REALM_A, 'idle', 'system'],
      [REALM_B, 'expired', 'system'],
    ]);
    expect(notices.find((notice) => notice.reason === 'idle')?.sessions[0].clients).toEqual([
      expect.objectContaining({ clientId: 'app' }),
    ]);
    expect(await service.endLapsed()).toEqual({ ended: 0 });
  });

  it('marks only sessions the service already treats as absent', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 600, maxLifespanSeconds: 3600 });
    const sids: string[] = [];
    for (let i = 0; i < 6; i++) {
      sids.push(await signInAt());
      clock.advance(12 * MINUTE);
    }
    const absentBefore = new Set<string>();
    for (const sid of sids) {
      // Read without touching: a get on a live session would move last_seen_at.
      const row = store.row(sid);
      if (row === undefined) continue;
      const idleEnd = row.lastSeenAt + 600 * SECOND;
      const absoluteEnd = Math.min(row.expiresAt, row.createdAt + 3600 * SECOND);
      if (clock.now() >= Math.min(idleEnd, absoluteEnd)) absentBefore.add(sid);
    }

    await service.endLapsed({ batchSize: 2 });

    for (const sid of sids) {
      expect(store.row(sid)?.revokedAt !== null, sid).toBe(absentBefore.has(sid));
    }
  });

  it('writes every tombstone of a batch before it tells any listener, whatever realms it spans', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 60 });
    store.putRealm(REALM_B, { idleTimeoutSeconds: 60 });
    const sids: string[] = [];
    for (let i = 0; i < 6; i++) {
      sids.push(await signInAt({ realmId: i % 2 === 0 ? REALM_A : REALM_B }));
    }
    clock.advance(HOUR);
    const tombstonesAtFirstNotice: number[] = [];
    service.onSessionsEnded(() => {
      tombstonesAtFirstNotice.push(cache.calls.tombstones);
    });

    expect(await service.endLapsed()).toEqual({ ended: 6 });

    expect(tombstonesAtFirstNotice[0]).toBe(6);
    expect(notices.map((notice) => notice.realmId).sort()).toEqual([REALM_A, REALM_B]);
  });

  it('stops between batches when its signal is aborted', async () => {
    store.putRealm(REALM_A, { idleTimeoutSeconds: 60 });
    for (let i = 0; i < 4; i++) await signInAt();
    clock.advance(HOUR);
    const controller = new AbortController();
    service.onSessionsEnded(() => controller.abort(new Error('stop')));

    await expect(service.endLapsed({ batchSize: 2, signal: controller.signal })).rejects.toThrow(
      'stop'
    );
    expect(noticedSids()).toHaveLength(2);
  });
});

describe('purge', () => {
  it('deletes the rows that ended or expired before the cut-off, and leaves the rest', async () => {
    const longEnded = await signInAt();
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid: longEnded,
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });
    const longExpired = await signInAt();
    clock.advance(31 * DAY);
    const recentlyEnded = await signInAt();
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid: recentlyEnded,
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });
    const live = await signInAt();

    const result = await service.purge({ endedBefore: clock.now() - 30 * DAY, batchSize: 1 });

    expect(result).toEqual({ deleted: 2 });
    expect(store.row(longEnded)).toBeUndefined();
    expect(store.row(longExpired)).toBeUndefined();
    expect(store.row(recentlyEnded)).toBeDefined();
    expect(store.row(live)).toBeDefined();
    expect(await service.get({ realmId: REALM_A, sid: live })).not.toBeNull();
    // Batches of one: two deletions, then the batch that finds no row.
    expect(store.calls.purgeBatches).toBe(3);
  });

  it('stops between batches when its signal is aborted', async () => {
    const controller = new AbortController();
    controller.abort(new Error('stop'));

    await expect(
      service.purge({ endedBefore: clock.now(), signal: controller.signal })
    ).rejects.toThrow('stop');
    expect(store.calls.purgeBatches).toBe(0);
  });
});

describe('onSessionsEnded', () => {
  it('runs after Postgres has the end and the cache has the tombstone', async () => {
    const sid = await signInAt();
    const seen: unknown[] = [];
    service.onSessionsEnded(async () => {
      seen.push(store.row(sid)?.revokedReason, await cache.read(REALM_A, sid));
    });

    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid,
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });

    expect(seen).toEqual(['sign_out', { kind: 'revoked' }]);
  });

  it('keeps the revocation and the other listeners when one listener throws', async () => {
    const sid = await signInAt();
    const late = vi.fn();
    service.onSessionsEnded(() => {
      throw new Error('listener broke');
    });
    service.onSessionsEnded(late);

    const result = await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid,
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });

    expect(result.outcome).toBe('ended');
    expect(late).toHaveBeenCalledTimes(1);
    expect(notices).toHaveLength(1);
    expect(warn).toHaveBeenCalledWith(
      expect.objectContaining({ realmId: REALM_A, reason: 'sign_out', sessions: 1 }),
      expect.stringContaining('listener failed')
    );
  });

  it('stops calling a listener once it is removed', async () => {
    const listener = vi.fn();
    const remove = service.onSessionsEnded(listener);
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid: await signInAt(),
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });
    remove();
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid: await signInAt(),
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });

    expect(listener).toHaveBeenCalledTimes(1);
    expect(notices).toHaveLength(2);
  });

  it('is told nothing when a call ends no session', async () => {
    await service.revokeAllForUser({
      realmId: REALM_A,
      userId: ALICE,
      reason: 'sign_out_everywhere',
      actor: ALICE_ACTOR,
    });
    await service.revoke({
      realmId: REALM_A,
      userId: ALICE,
      sid: '0199a000-0000-7000-8000-0000000000ff',
      reason: 'sign_out',
      actor: ALICE_ACTOR,
    });

    expect(notices).toEqual([]);
  });
});
