import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

import {
  endBrowserSessions,
  resolveBrowserSession,
  saveBrowserSession,
  trackBrowserSession,
} from './browser-session';
import { type BrowserSessionData, SESSION_COOKIE_NAME, signSessionId } from './session-cookie';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = 'sess-1';
const SESSION = { userId: USER_ID, sessionId: SESSION_ID, createdAt: Date.now() };
/** `SESSION_COOKIE_TTL` above, in milliseconds. */
const TTL_MS = 3600 * 1000;

function sessionAged(ageMs: number): BrowserSessionData {
  return { userId: USER_ID, sessionId: SESSION_ID, createdAt: Date.now() - ageMs };
}

const users = { findById: vi.fn() };
const sessionUtils = {
  getSession: vi.fn(),
  setSession: vi.fn().mockResolvedValue(undefined),
  deleteSession: vi.fn().mockResolvedValue(undefined),
};
const fastify = { repositories: { users }, sessionUtils } as unknown as FastifyInstance;

function makeRequest(cookie?: string): FastifyRequest {
  return { headers: cookie ? { cookie } : {} } as FastifyRequest;
}

function makeReply() {
  const headers: Record<string, string> = {};
  const reply = {
    header(k: string, v: string) {
      headers[k] = v;
      return reply;
    },
  } as unknown as FastifyReply;
  return { reply, headers };
}

const liveCookie = `${SESSION_COOKIE_NAME}=${signSessionId(SESSION_ID)}`;

beforeEach(() => {
  vi.clearAllMocks();
  sessionUtils.getSession.mockResolvedValue(SESSION);
  users.findById.mockResolvedValue({ id: USER_ID, enabled: true });
});

describe('resolveBrowserSession', () => {
  it('returns the session of an enabled user', async () => {
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(liveCookie), reply)).resolves.toEqual(
      SESSION
    );
    expect(users.findById).toHaveBeenCalledWith(USER_ID);
    expect(headers['Set-Cookie']).toBeUndefined();
  });

  it('returns null without a cookie or with a bad signature', async () => {
    const { reply } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(), reply)).resolves.toBeNull();
    await expect(
      resolveBrowserSession(fastify, makeRequest(`${SESSION_COOKIE_NAME}=${SESSION_ID}.bad`), reply)
    ).resolves.toBeNull();
    expect(sessionUtils.getSession).not.toHaveBeenCalled();
  });

  it('clears a stale cookie whose session is gone from Redis', async () => {
    sessionUtils.getSession.mockResolvedValue(null);
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(liveCookie), reply)
    ).resolves.toBeNull();
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
    expect(users.findById).not.toHaveBeenCalled();
  });

  it('ends the session of a user disabled after signing in', async () => {
    users.findById.mockResolvedValue({ id: USER_ID, enabled: false });
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(liveCookie), reply)
    ).resolves.toBeNull();
    expect(sessionUtils.deleteSession).toHaveBeenCalledWith(SESSION_ID);
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
  });

  it('ends the session of a user that no longer exists', async () => {
    users.findById.mockResolvedValue(undefined);
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(liveCookie), reply)
    ).resolves.toBeNull();
    expect(sessionUtils.deleteSession).toHaveBeenCalledWith(SESSION_ID);
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
  });
});

describe('absolute session lifetime (SESSION_COOKIE_TTL from createdAt)', () => {
  it('returns a session younger than SESSION_COOKIE_TTL', async () => {
    const stored = sessionAged(TTL_MS - 60_000);
    sessionUtils.getSession.mockResolvedValue(stored);
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(liveCookie), reply)).resolves.toEqual(
      stored
    );
    expect(headers['Set-Cookie']).toBeUndefined();
  });

  it('refuses and ends a session older than SESSION_COOKIE_TTL even though Redis still holds it', async () => {
    // A replayed cookie whose record kept being rewritten must not outlive the
    // lifetime the browser's own cookie was given at sign-in.
    sessionUtils.getSession.mockResolvedValue(sessionAged(TTL_MS + 1000));
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(liveCookie), reply)
    ).resolves.toBeNull();
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
    expect(sessionUtils.deleteSession).toHaveBeenCalledWith(SESSION_ID);
    expect(users.findById).not.toHaveBeenCalled();
  });

  it('refuses a record with no usable createdAt', async () => {
    sessionUtils.getSession.mockResolvedValue({ userId: USER_ID, sessionId: SESSION_ID });
    const { reply } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(liveCookie), reply)
    ).resolves.toBeNull();
  });
});

describe('saveBrowserSession', () => {
  it('stores the record for the remainder of its lifetime, not a fresh SESSION_COOKIE_TTL', async () => {
    const session = { ...sessionAged(TTL_MS - 900_000), csrfToken: 'token' };

    await saveBrowserSession(fastify, session);

    expect(sessionUtils.setSession).toHaveBeenCalledOnce();
    const [sessionId, data, ttl] = sessionUtils.setSession.mock.calls[0];
    expect(sessionId).toBe(SESSION_ID);
    expect(data).toEqual(session);
    expect(ttl).toBeGreaterThan(890);
    expect(ttl).toBeLessThanOrEqual(900);
  });

  it('never hands Redis a non-positive TTL', async () => {
    await saveBrowserSession(fastify, sessionAged(TTL_MS + 5000));

    expect(sessionUtils.setSession.mock.calls[0][2]).toBe(1);
  });
});

describe('per-user browser-session index (logout ends every session)', () => {
  function makeRedis(members: string[] = []) {
    const chain = {
      sadd: vi.fn(() => chain),
      expire: vi.fn(() => chain),
      exec: vi.fn().mockResolvedValue([]),
    };
    return {
      chain,
      multi: vi.fn(() => chain),
      smembers: vi.fn().mockResolvedValue(members),
      del: vi.fn().mockResolvedValue(1),
    };
  }

  it('records a new session under its user, expiring with the longest-lived session', async () => {
    const redis = makeRedis();
    const withRedis = { ...fastify, redis } as unknown as FastifyInstance;

    await trackBrowserSession(withRedis, USER_ID, 'sess-new');

    const key = `user-browser-sessions:${USER_ID}`;
    expect(redis.chain.sadd).toHaveBeenCalledWith(key, 'sess-new');
    // A session never outlives SESSION_COOKIE_TTL from its creation, so the
    // index set at the newest creation outlives every session in it.
    expect(redis.chain.expire).toHaveBeenCalledWith(key, 3600);
    expect(redis.chain.exec).toHaveBeenCalledOnce();
  });

  it('ends every recorded session of the user and drops the index', async () => {
    const redis = makeRedis(['sess-a', 'sess-b']);
    const withRedis = { ...fastify, redis } as unknown as FastifyInstance;

    await expect(endBrowserSessions(withRedis, USER_ID)).resolves.toEqual(['sess-a', 'sess-b']);

    expect(redis.smembers).toHaveBeenCalledWith(`user-browser-sessions:${USER_ID}`);
    expect(sessionUtils.deleteSession).toHaveBeenCalledWith('sess-a');
    expect(sessionUtils.deleteSession).toHaveBeenCalledWith('sess-b');
    expect(redis.del).toHaveBeenCalledWith(`user-browser-sessions:${USER_ID}`);
  });
});
