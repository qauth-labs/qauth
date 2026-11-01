import { TemporarilyUnavailableError } from '@qauth-labs/shared-errors';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

import {
  type BrowserSessionFixture,
  createBrowserSessionFixture,
  sessionCookie,
} from '../../testing/browser-sessions';
import { createFakeCookieSigner } from '../../testing/cookie-keys';
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
    signer: sessions.signer,
    redis: sessions.redis,
    log: { warn: vi.fn() },
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

  it('writes nothing to Redis for a sign-in without an identifier: no side record, no per-user index (#912)', async () => {
    await createBrowserSession(fastify, makeRequest(), { realmId: REALM.id, userId: USER_ID });

    // `/auth/logout` finds the user's sessions in Postgres.
    expect(sessions.redis.multi).not.toHaveBeenCalled();
    expect(sessions.redis.hset).not.toHaveBeenCalled();
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

  it('returns null without a cookie, and sets none', async () => {
    const { reply, headers } = makeReply();

    await expect(resolveBrowserSession(fastify, makeRequest(), reply)).resolves.toBeNull();
    expect(sessions.service.get).not.toHaveBeenCalled();
    expect(headers['Set-Cookie']).toBeUndefined();
  });

  it('clears a cookie that does not verify, without looking a session up (#493)', async () => {
    const { session, cookie } = await sessions.signIn({ realmId: REALM.id, userId: USER_ID });
    const value = cookie.slice(cookie.indexOf('=') + 1);
    const [kid, payload, mac] = value.split('.');

    for (const bad of [
      'sess-1.bad',
      // The format before the realm cookie keys: `<sid>.<hmac>`.
      `${session.sid}.${mac}`,
      `${kid}.${payload}.${mac.startsWith('A') ? 'B' : 'A'}${mac.slice(1)}`,
      `unknown-kid.${payload}.${mac}`,
    ]) {
      const { reply, headers } = makeReply();
      await expect(
        resolveBrowserSession(fastify, makeRequest(`${SESSION_COOKIE_NAME}=${bad}`), reply)
      ).resolves.toBeNull();
      expect(headers['Set-Cookie'], bad).toBe(
        `${SESSION_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`
      );
    }
    expect(sessions.service.get).not.toHaveBeenCalled();
  });

  it('keeps a cookie that names a key this process may not read again yet (#493)', async () => {
    const { cookie } = await sessions.signIn({ realmId: REALM.id, userId: USER_ID });
    const [, payload, mac] = cookie.slice(cookie.indexOf('=') + 1).split('.');

    // The first unknown kid makes the ring read the signer again; it holds no
    // such key, so that cookie is cleared.
    const first = makeReply();
    await expect(
      resolveBrowserSession(
        fastify,
        makeRequest(`${SESSION_COOKIE_NAME}=first-unknown.${payload}.${mac}`),
        first.reply
      )
    ).resolves.toBeNull();
    expect(first.headers['Set-Cookie']).toContain('Max-Age=0');

    // A second within five seconds is not read for: it may be a key another
    // node started signing with, so it is left for the next request.
    const second = makeReply();
    await expect(
      resolveBrowserSession(
        fastify,
        makeRequest(`${SESSION_COOKIE_NAME}=second-unknown.${payload}.${mac}`),
        second.reply
      )
    ).resolves.toBeNull();
    expect(second.headers['Set-Cookie']).toBeUndefined();
    expect(sessions.service.get).not.toHaveBeenCalled();
  });

  it('fails, and keeps the cookie, when the signer cannot answer', async () => {
    const { cookie } = await sessions.signIn({ realmId: REALM.id, userId: USER_ID });
    const down = createFakeCookieSigner();
    down.getCookieSecrets.mockRejectedValue(new TemporarilyUnavailableError(60));
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession({ ...fastify, signer: down } as never, makeRequest(cookie), reply)
    ).rejects.toBeInstanceOf(TemporarilyUnavailableError);
    expect(headers['Set-Cookie']).toBeUndefined();
  });

  it('clears a stale cookie whose session the service does not hold', async () => {
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(
        fastify,
        makeRequest(await sessionCookie(fastify, { sid: 'gone', realmId: REALM.id })),
        reply
      )
    ).resolves.toBeNull();
    expect(sessions.service.get).toHaveBeenCalledWith({ realmId: REALM.id, sid: 'gone' });
    expect(headers['Set-Cookie']).toContain('Max-Age=0');
    expect(users.findById).not.toHaveBeenCalled();
  });

  it('finds no session for a cookie of another realm (ADR-019 Decision 1)', async () => {
    const { cookie } = await sessions.signIn({ realmId: OTHER_REALM.id, userId: USER_ID });
    const { reply, headers } = makeReply();

    await expect(
      resolveBrowserSession(fastify, makeRequest(cookie, REALM), reply)
    ).resolves.toBeNull();
    // The cookie's MAC names its realm (#493): it does not verify here, so no
    // session is even looked up.
    expect(sessions.service.get).not.toHaveBeenCalled();
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
  const SIGN_OUT_EVERYWHERE = {
    realmId: REALM.id,
    userId: USER_ID,
    reason: 'sign_out_everywhere',
    actor: { type: 'user', id: USER_ID },
  };

  it('ends every live session of the user in the realm through the service, whatever Redis holds (#912)', async () => {
    const a = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      identifier: 'alice@example.com',
    });
    const b = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
    });
    const otherUser = sessions.service.seed({ realmId: REALM.id, userId: 'another-user' });
    const otherRealm = sessions.service.seed({ realmId: OTHER_REALM.id, userId: USER_ID });
    // A session Redis knows nothing of: signed in on another node, its side
    // record evicted, or gone with a Redis restart or failover.
    const unknownToRedis = sessions.service.seed({ realmId: REALM.id, userId: USER_ID });

    await expect(endBrowserSessions(fastify, REALM.id, USER_ID)).resolves.toEqual(
      [a.sid, b.sid, unknownToRedis.sid].sort()
    );

    expect(sessions.service.revokeAllForUser).toHaveBeenCalledExactlyOnceWith(SIGN_OUT_EVERYWHERE);
    expect(sessions.service.revoke).not.toHaveBeenCalled();
    for (const sid of [a.sid, b.sid, unknownToRedis.sid]) {
      expect(sessions.service.sessions.has(sid)).toBe(false);
    }
    // Another user's session and the user's session in another realm stay.
    expect(sessions.service.sessions.has(otherUser.sid)).toBe(true);
    expect(sessions.service.sessions.has(otherRealm.sid)).toBe(true);
    // The ended session's side record goes with it.
    expect(sessions.redis.hashes.size).toBe(0);
  });

  it('drops the side records of the sessions it ended, and only theirs', async () => {
    const a = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      identifier: 'alice@example.com',
    });
    const b = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      identifier: 'alice@example.com',
    });
    const other = await sessions.signIn({
      realmId: REALM.id,
      userId: 'another-user',
      side: { identifier: 'bob@example.com' },
    });

    await endBrowserSessions(fastify, REALM.id, USER_ID);

    expect(sessions.redis.del).toHaveBeenCalledTimes(2);
    expect(sessions.redis.del).toHaveBeenCalledWith(`browser-session-side:${REALM.id}:${a.sid}`);
    expect(sessions.redis.del).toHaveBeenCalledWith(`browser-session-side:${REALM.id}:${b.sid}`);
    expect([...sessions.redis.hashes.keys()]).toEqual([
      `browser-session-side:${REALM.id}:${other.session.sid}`,
    ]);
  });

  it('still answers the sessions it ended when Redis cannot drop their side records', async () => {
    const a = await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      identifier: 'alice@example.com',
    });
    const redisDown = new Error('Connection is closed.');
    sessions.redis.del.mockRejectedValue(redisDown);

    await expect(endBrowserSessions(fastify, REALM.id, USER_ID)).resolves.toEqual([a.sid]);

    expect(sessions.service.sessions.has(a.sid)).toBe(false);
    expect(fastify.log.warn).toHaveBeenCalledExactlyOnceWith(
      { err: redisDown, realmId: REALM.id, failed: 1 },
      expect.stringContaining('expire with the sessions')
    );
  });

  it('throws when the service cannot end the sessions, and touches nothing in Redis', async () => {
    await createBrowserSession(fastify, makeRequest(), {
      realmId: REALM.id,
      userId: USER_ID,
      identifier: 'alice@example.com',
    });
    const storeDown = new Error('connection terminated');
    sessions.service.revokeAllForUser.mockRejectedValue(storeDown);

    await expect(endBrowserSessions(fastify, REALM.id, USER_ID)).rejects.toBe(storeDown);

    expect(sessions.redis.del).not.toHaveBeenCalled();
    expect(sessions.redis.hashes.size).toBe(1);
  });

  it('ends nothing for a user with no live session', async () => {
    await expect(endBrowserSessions(fastify, REALM.id, USER_ID)).resolves.toEqual([]);
    expect(sessions.service.revokeAllForUser).toHaveBeenCalledExactlyOnceWith(SIGN_OUT_EVERYWHERE);
    expect(fastify.log.warn).not.toHaveBeenCalled();
  });
});
