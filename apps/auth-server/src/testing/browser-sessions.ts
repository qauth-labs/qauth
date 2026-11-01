import { randomUUID } from 'node:crypto';

import type {
  BrowserSession,
  EndedSession,
  ListedSession,
  SessionAssuranceLevel,
  SessionRecord,
  SessionRevokedReason,
  SessionsEndedListener,
  SessionService,
} from '@qauth-labs/fastify-plugin-sessions';
import type { FastifyInstance } from 'fastify';
import { type Mock, vi } from 'vitest';

import type { CookieKeyHolder } from '../app/helpers/cookie-keys';
import { SESSION_COOKIE_NAME, signSessionCookie } from '../app/helpers/session-cookie';
import {
  readSessionSideRecord,
  type SessionSideRecord,
  writeSessionSideRecord,
} from '../app/helpers/session-side-record';
import { createFakeCookieSigner, type FakeCookieSigner } from './cookie-keys';

/** How long a session the fake creates lasts: an hour, as tests set `SESSION_COOKIE_TTL`. */
export const FAKE_SESSION_LIFETIME_MS = 3_600_000;

/** A session to put in the fake service as if a sign-in had created it. */
export interface FakeSessionSeed {
  /** Defaults to a random UUID. */
  sid?: string;
  realmId: string;
  userId: string;
  /** Epoch milliseconds; defaults to now. */
  authTime?: number;
  assuranceLevel?: SessionAssuranceLevel | null;
  /** Epoch milliseconds; defaults to {@link FAKE_SESSION_LIFETIME_MS} after `authTime`. */
  expiresAt?: number;
}

/**
 * A stand-in for `fastify.sessionService` (#488) for unit tests, in place of
 * the old `sessionUtils` fakes. It keeps the service's contract where routes
 * rely on it: `get` finds a session only in its own realm and only before its
 * end, `create` always makes a new `sid`, `revoke` ends a session for good
 * and reports a second call, the bulk revocations end each session once and
 * tell the `onSessionsEnded` listeners. It holds no client registry, so an
 * ended session served no client. Each method is a `vi.fn`, so a test can
 * assert calls or make one fail.
 */
export interface FakeSessionService extends SessionService {
  create: Mock<SessionService['create']>;
  get: Mock<SessionService['get']>;
  revoke: Mock<SessionService['revoke']>;
  revokeAllForUser: Mock<SessionService['revokeAllForUser']>;
  revokeAllForRealm: Mock<SessionService['revokeAllForRealm']>;
  endLapsed: Mock<SessionService['endLapsed']>;
  purge: Mock<SessionService['purge']>;
  listForUser: Mock<SessionService['listForUser']>;
  listForClient: Mock<SessionService['listForClient']>;
  onSessionsEnded: Mock<SessionService['onSessionsEnded']>;
  /** The live sessions, by `sid`. */
  readonly sessions: Map<string, BrowserSession>;
  /** Store a live session without counting a `create` call. */
  seed(seed: FakeSessionSeed): BrowserSession;
}

function browserSession(seed: FakeSessionSeed & { amr?: readonly string[] }): BrowserSession {
  const authTime = seed.authTime ?? Date.now();
  return {
    sid: seed.sid ?? randomUUID(),
    realmId: seed.realmId,
    userId: seed.userId,
    authTime,
    amr: Object.freeze([...(seed.amr ?? [])]),
    assuranceLevel: seed.assuranceLevel ?? null,
    createdAt: authTime,
    lastSeenAt: authTime,
    expiresAt: seed.expiresAt ?? authTime + FAKE_SESSION_LIFETIME_MS,
    idleExpiresAt: null,
  };
}

/** The row a fake session ends as. */
function endedRecord(session: BrowserSession, reason: SessionRevokedReason): SessionRecord {
  return {
    id: session.sid,
    realmId: session.realmId,
    userId: session.userId,
    authTime: session.authTime,
    amr: [...session.amr],
    assuranceLevel: session.assuranceLevel,
    ipAddress: null,
    userAgent: null,
    expiresAt: session.expiresAt,
    revokedAt: Date.now(),
    revokedReason: reason,
    createdAt: session.createdAt,
    lastSeenAt: session.lastSeenAt,
  };
}

/** Create a {@link FakeSessionService}. */
export function createFakeSessionService(): FakeSessionService {
  const sessions = new Map<string, BrowserSession>();
  const ended = new Map<string, SessionRecord>();
  const listeners = new Set<SessionsEndedListener>();

  /** End `matching` sessions, record them and tell the listeners. */
  async function endAll(
    realmId: string,
    reason: SessionRevokedReason,
    actor: Parameters<SessionService['revoke']>[0]['actor'],
    matching: (session: BrowserSession) => boolean
  ): Promise<EndedSession[]> {
    const done: EndedSession[] = [];
    for (const session of [...sessions.values()].sort((a, b) => (a.sid < b.sid ? -1 : 1))) {
      if (session.realmId !== realmId || !matching(session)) continue;
      sessions.delete(session.sid);
      const record = endedRecord(session, reason);
      ended.set(session.sid, record);
      done.push({ session: record, clients: [] });
    }
    if (done.length > 0) {
      for (const listener of [...listeners]) {
        await listener({ realmId, reason, actor, sessions: done });
      }
    }
    return done;
  }

  function listed(session: BrowserSession): ListedSession {
    return {
      ...session,
      ipAddress: null,
      userAgent: null,
      state: Date.now() < session.expiresAt ? 'live' : 'expired',
      revokedAt: null,
      revokedReason: null,
      clients: [],
    };
  }

  return {
    sessions,
    seed(seed) {
      const session = browserSession(seed);
      sessions.set(session.sid, session);
      return session;
    },
    create: vi.fn<SessionService['create']>(async (input) => {
      const session = browserSession({
        realmId: input.realmId,
        userId: input.userId,
        authTime: input.authTime,
        assuranceLevel: input.assuranceLevel ?? null,
        amr: input.amr,
      });
      sessions.set(session.sid, session);
      return session;
    }),
    get: vi.fn<SessionService['get']>(async ({ realmId, sid }) => {
      const session = sessions.get(sid);
      if (session === undefined || session.realmId !== realmId) return null;
      return Date.now() < session.expiresAt ? session : null;
    }),
    revoke: vi.fn<SessionService['revoke']>(async ({ realmId, sid, userId, reason, actor }) => {
      if (actor.type === 'user' && userId === undefined) {
        throw new RangeError('A user ends a session only by naming its owner: pass userId');
      }
      const owned = (session: { userId: string }) =>
        userId === undefined || session.userId === userId;
      const before = ended.get(sid);
      if (before !== undefined && before.realmId === realmId) {
        return owned(before)
          ? { outcome: 'already_ended', session: before }
          : { outcome: 'not_found' };
      }
      const [done] = await endAll(
        realmId,
        reason,
        actor,
        (session) => session.sid === sid && owned(session)
      );
      return done === undefined
        ? { outcome: 'not_found' }
        : { outcome: 'ended', session: done.session, clients: done.clients };
    }),
    revokeAllForUser: vi.fn<SessionService['revokeAllForUser']>(async (input) => ({
      sessions: await endAll(
        input.realmId,
        input.reason,
        input.actor,
        (session) =>
          session.userId === input.userId &&
          session.sid !== input.exceptSid &&
          (input.createdBefore === undefined || session.createdAt < input.createdBefore)
      ),
    })),
    revokeAllForRealm: vi.fn<SessionService['revokeAllForRealm']>(async (input) => {
      const done = await endAll(
        input.realmId,
        input.reason,
        input.actor,
        (session) => input.activeSince === undefined || session.lastSeenAt >= input.activeSince
      );
      return { ended: done.length, batches: done.length === 0 ? 0 : 1 };
    }),
    endLapsed: vi.fn<SessionService['endLapsed']>(async () => ({ ended: 0 })),
    purge: vi.fn<SessionService['purge']>(async () => ({ deleted: 0 })),
    listForUser: vi.fn<SessionService['listForUser']>(async ({ realmId, userId }) => ({
      items: [...sessions.values()]
        .filter((session) => session.realmId === realmId && session.userId === userId)
        .sort((a, b) => b.createdAt - a.createdAt)
        .map(listed),
      nextCursor: null,
    })),
    listForClient: vi.fn<SessionService['listForClient']>(async () => ({
      items: [],
      nextCursor: null,
    })),
    onSessionsEnded: vi.fn<SessionService['onSessionsEnded']>((listener) => {
      listeners.add(listener);
      return () => {
        listeners.delete(listener);
      };
    }),
  };
}

/** One queued command of {@link MemorySessionRedis.multi}. */
type QueuedCommand = () => Promise<unknown>;

/** The condition of a Redis 7 `PEXPIREAT`: set only when it holds. */
export type ExpiryCondition = 'NX' | 'XX' | 'GT' | 'LT';

/** A `MULTI` block: the commands the browser-session helpers queue. */
export interface MemorySessionRedisMulti {
  hset(key: string, fields: Record<string, string>): MemorySessionRedisMulti;
  pexpireat(key: string, at: number, condition?: ExpiryCondition): MemorySessionRedisMulti;
  exec(): Promise<[Error | null, unknown][]>;
}

/**
 * The Redis commands the browser-session helpers send for the side record
 * (`helpers/session-side-record.ts`), held in memory. Each is a `vi.fn`; spread it into a test's
 * own `redis` stub beside the commands other code needs.
 */
export interface MemorySessionRedis {
  readonly hashes: Map<string, Map<string, string>>;
  /** The `PEXPIREAT` deadline last set on each key, in epoch milliseconds. */
  readonly expiries: Map<string, number>;
  hgetall: Mock<(key: string) => Promise<Record<string, string>>>;
  hset: Mock<(key: string, fields: Record<string, string>) => Promise<number>>;
  hdel: Mock<(key: string, ...fields: string[]) => Promise<number>>;
  pexpireat: Mock<(key: string, at: number, condition?: ExpiryCondition) => Promise<number>>;
  del: Mock<(...keys: string[]) => Promise<number>>;
  multi: Mock<() => MemorySessionRedisMulti>;
  /** Drop every key whose deadline is at or before `now`, as Redis would by then. */
  dropExpired(now: number): void;
}

/** Create a {@link MemorySessionRedis}. */
export function createMemorySessionRedis(): MemorySessionRedis {
  const hashes = new Map<string, Map<string, string>>();
  const expiries = new Map<string, number>();

  const redis: MemorySessionRedis = {
    hashes,
    expiries,
    hgetall: vi.fn(async (key: string) => Object.fromEntries(hashes.get(key) ?? [])),
    hset: vi.fn(async (key: string, fields: Record<string, string>) => {
      const hash = hashes.get(key) ?? new Map<string, string>();
      let added = 0;
      for (const [field, value] of Object.entries(fields)) {
        if (!hash.has(field)) added += 1;
        hash.set(field, value);
      }
      hashes.set(key, hash);
      return added;
    }),
    hdel: vi.fn(async (key: string, ...fields: string[]) => {
      const hash = hashes.get(key);
      if (hash === undefined) return 0;
      const removed = fields.filter((field) => hash.delete(field)).length;
      if (hash.size === 0) hashes.delete(key);
      return removed;
    }),
    pexpireat: vi.fn(async (key: string, at: number, condition?: ExpiryCondition) => {
      if (!hashes.has(key)) return 0;
      // Redis 7 semantics: a key without a deadline counts as never ending,
      // so GT never sets one on it and LT always does.
      const current = expiries.get(key);
      const allowed =
        condition === 'NX'
          ? current === undefined
          : condition === 'XX'
            ? current !== undefined
            : condition === 'GT'
              ? current !== undefined && at > current
              : condition === 'LT'
                ? current === undefined || at < current
                : true;
      if (!allowed) return 0;
      expiries.set(key, at);
      return 1;
    }),
    del: vi.fn(async (...keys: string[]) => {
      let removed = 0;
      for (const key of keys) {
        if (hashes.delete(key)) removed += 1;
        expiries.delete(key);
      }
      return removed;
    }),
    multi: vi.fn(() => {
      const queued: QueuedCommand[] = [];
      const block: MemorySessionRedisMulti = {
        hset(key, fields) {
          queued.push(() => redis.hset(key, fields));
          return block;
        },
        pexpireat(key, at, condition) {
          queued.push(() => redis.pexpireat(key, at, condition));
          return block;
        },
        async exec() {
          const results: [Error | null, unknown][] = [];
          for (const command of queued) results.push([null, await command()]);
          return results;
        },
      };
      return block;
    }),
    dropExpired(now: number) {
      for (const [key, at] of expiries) {
        if (at > now) continue;
        hashes.delete(key);
        expiries.delete(key);
      }
    },
  };
  return redis;
}

/** The values to seed into a session's side record. */
export interface FakeSideRecordSeed {
  identifier?: string;
  csrfToken?: string;
  apiCsrfToken?: string;
  /** Bound scopes by `client_id`. */
  consentScopes?: Record<string, string[]>;
  /** Bound resources by `client_id`; each client needs `consentScopes` too. */
  consentResources?: Record<string, string[]>;
  /**
   * Whether the bound page was an agent's, by `client_id`; each client needs
   * `consentScopes` too. A client left out was shown as no agent.
   */
  consentAgent?: Record<string, boolean>;
}

/**
 * A fake session service, the Redis the side record lives in, and the signer
 * the cookie keys come from (#493), together: what a unit test of a route
 * that reads the session cookie needs. Put
 * {@link service} on `fastify.sessionService`, {@link signer} on
 * `fastify.signer`, and spread {@link redis} into `fastify.redis`.
 */
export interface BrowserSessionFixture {
  service: FakeSessionService;
  redis: MemorySessionRedis;
  /** The cookie keys' signer: every realm has one. */
  signer: FakeCookieSigner;
  /**
   * A signed-in browser: a live session, its side record values, and the
   * `Cookie` header that names it.
   */
  signIn(
    seed: FakeSessionSeed & { side?: FakeSideRecordSeed }
  ): Promise<{ session: BrowserSession; cookie: string }>;
  /** The side record of `session`, as the routes read it. */
  sideRecord(session: Pick<BrowserSession, 'realmId' | 'sid'>): Promise<SessionSideRecord>;
}

/** Create a {@link BrowserSessionFixture}. */
export function createBrowserSessionFixture(): BrowserSessionFixture {
  const service = createFakeSessionService();
  const redis = createMemorySessionRedis();
  const signer = createFakeCookieSigner();
  const fastify = { redis } as unknown as FastifyInstance;
  return {
    service,
    redis,
    signer,
    async signIn({ side, ...seed }) {
      const session = service.seed(seed);
      if (side !== undefined) {
        await writeSessionSideRecord(fastify, session, {
          identifier: side.identifier,
          csrfToken: side.csrfToken,
          apiCsrfToken: side.apiCsrfToken,
        });
        for (const clientId of [
          ...Object.keys(side.consentResources ?? {}),
          ...Object.keys(side.consentAgent ?? {}),
        ]) {
          if (side.consentScopes?.[clientId] === undefined) {
            throw new Error(`seed consentScopes for ${clientId} with its other bindings`);
          }
        }
        for (const [clientId, scopes] of Object.entries(side.consentScopes ?? {})) {
          await writeSessionSideRecord(fastify, session, {
            consent: {
              clientId,
              scopes,
              resources: side.consentResources?.[clientId] ?? [],
              agent: side.consentAgent?.[clientId] ?? false,
            },
          });
        }
      }
      return { session, cookie: await sessionCookie({ signer }, session) };
    },
    sideRecord: (session) => readSessionSideRecord(fastify, session),
  };
}

/**
 * The `Cookie` header that carries `session` in a session cookie signed with
 * its realm's current cookie key from `fastify.signer` (#493).
 */
export async function sessionCookie(
  fastify: CookieKeyHolder,
  session: { readonly sid: string; readonly realmId: string }
): Promise<string> {
  return `${SESSION_COOKIE_NAME}=${await signSessionCookie(fastify, session)}`;
}
