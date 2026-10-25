import { randomUUID } from 'node:crypto';

import type {
  BrowserSession,
  SessionAssuranceLevel,
  SessionRecord,
  SessionService,
} from '@qauth-labs/fastify-plugin-sessions';
import type { FastifyInstance } from 'fastify';
import { type Mock, vi } from 'vitest';

import { SESSION_COOKIE_NAME, signSessionId } from '../app/helpers/session-cookie';
import {
  readSessionSideRecord,
  type SessionSideRecord,
  writeSessionSideRecord,
} from '../app/helpers/session-side-record';

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
 * end, `create` always makes a new `sid`, `revoke` ends a session for good.
 * Each method is a `vi.fn`, so a test can assert calls or make one fail.
 */
export interface FakeSessionService extends SessionService {
  create: Mock<SessionService['create']>;
  get: Mock<SessionService['get']>;
  revoke: Mock<SessionService['revoke']>;
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

/** Create a {@link FakeSessionService}. */
export function createFakeSessionService(): FakeSessionService {
  const sessions = new Map<string, BrowserSession>();
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
    revoke: vi.fn<SessionService['revoke']>(async ({ realmId, sid, reason }) => {
      const session = sessions.get(sid);
      if (session === undefined || session.realmId !== realmId) return null;
      sessions.delete(sid);
      const ended: SessionRecord = {
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
      return ended;
    }),
  };
}

/** One queued command of {@link MemorySessionRedis.multi}. */
type QueuedCommand = () => Promise<unknown>;

/** A `MULTI` block: the commands the browser-session helpers queue. */
export interface MemorySessionRedisMulti {
  hset(key: string, fields: Record<string, string>): MemorySessionRedisMulti;
  sadd(key: string, ...members: string[]): MemorySessionRedisMulti;
  pexpireat(key: string, at: number): MemorySessionRedisMulti;
  exec(): Promise<[Error | null, unknown][]>;
}

/**
 * The Redis commands the browser-session helpers send for the side record
 * (`helpers/session-side-record.ts`) and the per-user index of
 * `/auth/logout`, held in memory. Each is a `vi.fn`; spread it into a test's
 * own `redis` stub beside the commands other code needs.
 */
export interface MemorySessionRedis {
  readonly hashes: Map<string, Map<string, string>>;
  readonly sets: Map<string, Set<string>>;
  /** The `PEXPIREAT` deadline last set on each key, in epoch milliseconds. */
  readonly expiries: Map<string, number>;
  hgetall: Mock<(key: string) => Promise<Record<string, string>>>;
  hset: Mock<(key: string, fields: Record<string, string>) => Promise<number>>;
  hdel: Mock<(key: string, ...fields: string[]) => Promise<number>>;
  sadd: Mock<(key: string, ...members: string[]) => Promise<number>>;
  smembers: Mock<(key: string) => Promise<string[]>>;
  pexpireat: Mock<(key: string, at: number) => Promise<number>>;
  del: Mock<(...keys: string[]) => Promise<number>>;
  multi: Mock<() => MemorySessionRedisMulti>;
}

/** Create a {@link MemorySessionRedis}. */
export function createMemorySessionRedis(): MemorySessionRedis {
  const hashes = new Map<string, Map<string, string>>();
  const sets = new Map<string, Set<string>>();
  const expiries = new Map<string, number>();

  const redis: MemorySessionRedis = {
    hashes,
    sets,
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
    sadd: vi.fn(async (key: string, ...members: string[]) => {
      const set = sets.get(key) ?? new Set<string>();
      const before = set.size;
      for (const member of members) set.add(member);
      sets.set(key, set);
      return set.size - before;
    }),
    smembers: vi.fn(async (key: string) => [...(sets.get(key) ?? [])]),
    pexpireat: vi.fn(async (key: string, at: number) => {
      if (!hashes.has(key) && !sets.has(key)) return 0;
      expiries.set(key, at);
      return 1;
    }),
    del: vi.fn(async (...keys: string[]) => {
      let removed = 0;
      for (const key of keys) {
        if (hashes.delete(key) || sets.delete(key)) removed += 1;
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
        sadd(key, ...members) {
          queued.push(() => redis.sadd(key, ...members));
          return block;
        },
        pexpireat(key, at) {
          queued.push(() => redis.pexpireat(key, at));
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
}

/**
 * A fake session service and the Redis the side record and the logout index
 * live in, together: what a unit test of a route that reads the session
 * cookie needs. Put {@link service} on `fastify.sessionService` and spread
 * {@link redis} into `fastify.redis`.
 */
export interface BrowserSessionFixture {
  service: FakeSessionService;
  redis: MemorySessionRedis;
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
  const fastify = { redis } as unknown as FastifyInstance;
  return {
    service,
    redis,
    async signIn({ side, ...seed }) {
      const session = service.seed(seed);
      if (side !== undefined) {
        await writeSessionSideRecord(fastify, session, {
          identifier: side.identifier,
          csrfToken: side.csrfToken,
          apiCsrfToken: side.apiCsrfToken,
        });
        for (const clientId of Object.keys(side.consentResources ?? {})) {
          if (side.consentScopes?.[clientId] === undefined) {
            throw new Error(`seed consentScopes for ${clientId} with its consentResources`);
          }
        }
        for (const [clientId, scopes] of Object.entries(side.consentScopes ?? {})) {
          await writeSessionSideRecord(fastify, session, {
            consent: { clientId, scopes, resources: side.consentResources?.[clientId] ?? [] },
          });
        }
      }
      return { session, cookie: sessionCookie(session.sid) };
    },
    sideRecord: (session) => readSessionSideRecord(fastify, session),
  };
}

/** The `Cookie` header that carries `sid` in a signed session cookie. */
export function sessionCookie(sid: string): string {
  return `${SESSION_COOKIE_NAME}=${signSessionId(sid)}`;
}
