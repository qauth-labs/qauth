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
  type BrowserSessionFixture,
  createBrowserSessionFixture,
  sessionCookie,
} from '../../testing/browser-sessions';
import { testRealm } from '../../testing/request-realm';
import { createBrowserSession, endBrowserSessions, resolveBrowserSession } from './browser-session';
import { SESSION_COOKIE_NAME } from './session-cookie';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const REALM = testRealm({ id: '22222222-2222-4222-8222-222222222222' });
const OTHER_REALM = testRealm({ id: '33333333-3333-4333-8333-333333333333' });

const users = { findById: vi.fn() };
let sessions: BrowserSessionFixture;
let fastify: FastifyInstance;

function makeRequest(cookie?: string, realm = REALM): FastifyRequest {
  return {
    headers: cookie ? { cookie, 'user-agent': 'TestAgent/1.0' } : { 'user-agent': 'TestAgent/1.0' },
    ip: '203.0.113.7',
    realm,
  } as unknown as FastifyRequest;
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

beforeEach(() => {
  vi.clearAllMocks();
  sessions = createBrowserSessionFixture();
  fastify = {
    repositories: { users },
    sessionService: sessions.service,
    redis: sessions.redis,
  } as unknown as FastifyInstance;
  users.findById.mockResolvedValue({ id: USER_ID, enabled: true });
});

describe('createBrowserSession', () => {
  it('creates a session through the service with the request address and user agent', async () => {
    const before = Date.now();
    const session = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      identifier: 'alice@example.com',
    });

    expect(sessions.service.create).toHaveBeenCalledOnce();
    const input = sessions.service.create.mock.calls[0][0];
    expect(input).toMatchObject({
      realmId: REALM.id,
      userId: USER_ID,
      assuranceLevel: null,
      ipAddress: '203.0.113.7',
      userAgent: 'TestAgent/1.0',
    });
    expect(input.authTime).toBeGreaterThanOrEqual(before);
    expect(input.authTime).toBeLessThanOrEqual(Date.now());
    // The identifier is not a session column: it stays in the side record.
    expect(input).not.toHaveProperty('identifier');
    await expect(sessions.sideRecord(session)).resolves.toMatchObject({
      identifier: 'alice@example.com',
    });
  });

  it('counts the session from the issue time the sign-in took before reading the account (#748)', async () => {
    const issuedAt = Date.now() - 1500;
    await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      issuedAt,
    });

    expect(sessions.service.create.mock.calls[0][0].issuedAt).toBe(issuedAt);
  });

  it('carries the assurance level the authentication established', async () => {
    await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      assuranceLevel: 'high',
    });

    expect(sessions.service.create.mock.calls[0][0].assuranceLevel).toBe('high');
  });

  it('stores no address that is not one, and cuts the user agent as events do', async () => {
    const request = {
      headers: { 'user-agent': 'x'.repeat(5000) },
      ip: 'fe80::1%eth0-with-a-zone-id-that-is-far-too-long',
      realm: REALM,
    } as unknown as FastifyRequest;

    await createBrowserSession(fastify, request, { realmId: REALM.id, userId: USER_ID });

    const input = sessions.service.create.mock.calls[0][0];
    expect(input.ipAddress).toBeNull();
    expect(input.userAgent).toHaveLength(1024);
  });

  it('records the new session under its user, expiring with its absolute end', async () => {
    const session = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
    });

    const key = `user-browser-sessions:${USER_ID}`;
    expect(sessions.redis.sets.get(key)).toEqual(new Set([session.sid]));
    expect(sessions.redis.expiries.get(key)).toBe(session.expiresAt);
  });

  it('writes no side record for a sign-in without an identifier', async () => {
    await createBrowserSession(fastify, makeRequest(), { realmId: REALM.id, userId: USER_ID });

    expect(sessions.redis.hashes.size).toBe(0);
  });

  it('always makes a new session, whatever cookie the browser sent', async () => {
    const { cookie, session: old } = await sessions.signIn({ realmId: REALM.id, userId: USER_ID });

    const fresh = await createBrowserSession(fastify, makeRequest(cookie), {
      realmId: REALM.id,
      userId: USER_ID,
    });

    expect(fresh.sid).not.toBe(old.sid);
  });

  it('fails when the index cannot be written, so no untracked session reaches a cookie', async () => {
    sessions.redis.multi.mockReturnValueOnce({
      hset: vi.fn(),
      sadd() {
        return this;
      },
      pexpireat() {
        return this;
      },
      exec: vi.fn().mockResolvedValue([
        [null, 1],
        [new Error('OOM command not allowed'), null],
      ]),
    } as never);

    await expect(
      createBrowserSession(fastify, makeRequest(), { realmId: REALM.id, userId: USER_ID })
    ).rejects.toThrow('OOM');
  });
});

describe('resolveBrowserSession', () => {
  it('returns the session of an enabled user, looked up in the request realm', async () => {
    const { session, cookie } = await sessions.signIn({ realmId: REALM.id, userId: USER_ID });
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(cookie), reply)).resolves.toEqual(
      session
    );
    expect(sessions.service.get).toHaveBeenCalledWith({ realmId: REALM.id, sid: session.sid });
    // The session's user, looked up in the session's realm, the request's (#489).
    expect(users.findById).toHaveBeenCalledWith(REALM.id, USER_ID);
    expect(headers['Set-Cookie']).toBeUndefined();
  });

  it('returns null without a cookie or with a bad signature', async () => {
    const { reply } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(), reply)).resolves.toBeNull();
    await expect(
      resolveBrowserSession(fastify, makeRequest(`${SESSION_COOKIE_NAME}=sess-1.bad`), reply)
    ).resolves.toBeNull();
    expect(sessions.service.get).not.toHaveBeenCalled();
  });

  it('clears a stale cookie whose session the service does not hold', async () => {
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(sessionCookie('gone')), reply)
    ).resolves.toBeNull();
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
    expect(users.findById).not.toHaveBeenCalled();
  });

  it('finds no session for a cookie of another realm (ADR-019 Decision 1)', async () => {
    const { cookie } = await sessions.signIn({ realmId: OTHER_REALM.id, userId: USER_ID });
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(cookie, REALM), reply)
    ).resolves.toBeNull();
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
    expect(users.findById).not.toHaveBeenCalled();
  });

  it('finds no session past its absolute end', async () => {
    const { cookie } = await sessions.signIn({
      realmId: REALM.id,
      userId: USER_ID,
      expiresAt: Date.now() - 1,
    });
    const { reply } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(cookie), reply)).resolves.toBeNull();
  });

  it('revokes the session of a user disabled after signing in', async () => {
    users.findById.mockResolvedValue({ id: USER_ID, enabled: false });
    const { session, cookie } = await sessions.signIn({
      realmId: REALM.id,
      userId: USER_ID,
      side: { csrfToken: 'tok' },
    });
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(cookie), reply)).resolves.toBeNull();
    expect(sessions.service.revoke).toHaveBeenCalledWith({
      realmId: REALM.id,
      sid: session.sid,
      reason: 'admin',
      actor: { type: 'system' },
      userId: USER_ID,
    });
    expect(sessions.service.sessions.has(session.sid)).toBe(false);
    expect(sessions.redis.hashes.size).toBe(0);
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
  });

  it('revokes a session that began before the account was last disabled, once it is enabled again (#748)', async () => {
    const disabledAt = Date.now() - 60_000;
    users.findById.mockResolvedValue({ id: USER_ID, enabled: true, notValidBefore: disabledAt });
    const { session, cookie } = await sessions.signIn({
      realmId: REALM.id,
      userId: USER_ID,
      authTime: disabledAt - 60_000,
      side: { csrfToken: 'tok' },
    });
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(cookie), reply)).resolves.toBeNull();
    expect(sessions.service.revoke).toHaveBeenCalledWith({
      realmId: REALM.id,
      sid: session.sid,
      reason: 'admin',
      actor: { type: 'system' },
      userId: USER_ID,
    });
    expect(sessions.redis.hashes.size).toBe(0);
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
  });

  it('keeps a session that began after the account was enabled again (#748)', async () => {
    const disabledAt = Date.now() - 600_000;
    users.findById.mockResolvedValue({ id: USER_ID, enabled: true, notValidBefore: disabledAt });
    const { session, cookie } = await sessions.signIn({
      realmId: REALM.id,
      userId: USER_ID,
      authTime: disabledAt + 60_000,
    });
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(cookie), reply)).resolves.toEqual(
      session
    );
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    expect(headers['Set-Cookie']).toBeUndefined();
  });

  it('revokes the session of a user that no longer exists', async () => {
    users.findById.mockResolvedValue(undefined);
    const { session, cookie } = await sessions.signIn({ realmId: REALM.id, userId: USER_ID });
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(cookie), reply)).resolves.toBeNull();
    expect(sessions.service.revoke).toHaveBeenCalledWith(
      expect.objectContaining({ sid: session.sid })
    );
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
  });
});

describe('endBrowserSessions (logout ends every session)', () => {
  it('revokes every recorded session of the user, drops their side records and the index', async () => {
    const a = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      identifier: 'alice@example.com',
    });
    const b = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
    });

    await expect(endBrowserSessions(fastify, REALM.id, USER_ID)).resolves.toEqual([a.sid, b.sid]);

    for (const sid of [a.sid, b.sid]) {
      expect(sessions.service.revoke).toHaveBeenCalledWith({
        realmId: REALM.id,
        sid,
        reason: 'sign_out_everywhere',
        actor: { type: 'user', id: USER_ID },
        userId: USER_ID,
      });
    }
    expect(sessions.service.sessions.size).toBe(0);
    expect(sessions.redis.hashes.size).toBe(0);
    expect(sessions.redis.sets.has(`user-browser-sessions:${USER_ID}`)).toBe(false);
  });

  it('keeps the index until its latest session ends, when a newer one ends earlier', async () => {
    // The realm's lifetime shrank between the two sign-ins: the newer session
    // ends first. Its deadline must not pull the index in under the older one.
    const index = `user-browser-sessions:${USER_ID}`;
    const older = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
    });
    const create = sessions.service.create.getMockImplementation();
    if (create === undefined) throw new Error('the fake service has no create');
    const shorterEnd = older.expiresAt - 30 * 60_000;
    sessions.service.create.mockImplementationOnce(async (input) => ({
      ...(await create(input)),
      expiresAt: shorterEnd,
    }));
    const newer = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
    });
    expect(newer.expiresAt).toBe(shorterEnd);

    expect(sessions.redis.expiries.get(index)).toBe(older.expiresAt);

    // Past the newer session's end, the index is still there for logout.
    sessions.redis.dropExpired(shorterEnd + 1);
    await expect(endBrowserSessions(fastify, REALM.id, USER_ID)).resolves.toEqual([
      older.sid,
      newer.sid,
    ]);
    expect(sessions.service.revoke).toHaveBeenCalledWith({
      realmId: REALM.id,
      sid: older.sid,
      reason: 'sign_out_everywhere',
      actor: { type: 'user', id: USER_ID },
      userId: USER_ID,
    });
  });

  it('ends nothing for a user with no recorded session', async () => {
    await expect(endBrowserSessions(fastify, REALM.id, USER_ID)).resolves.toEqual([]);
    expect(sessions.service.revoke).not.toHaveBeenCalled();
  });
});
