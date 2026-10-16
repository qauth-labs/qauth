import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding',
    SESSION_COOKIE_TTL: 3600,
    SESSION_COOKIE_SECURE: false,
  },
}));

import { resolveBrowserSession } from './browser-session';
import { SESSION_COOKIE_NAME, signSessionId } from './session-cookie';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SESSION_ID = 'sess-1';
const SESSION = { userId: USER_ID, sessionId: SESSION_ID, createdAt: 1 };

const users = { findById: vi.fn() };
const sessionUtils = { getSession: vi.fn(), deleteSession: vi.fn().mockResolvedValue(undefined) };
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
