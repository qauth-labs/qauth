import { InvalidSessionCursorError } from '@qauth-labs/fastify-plugin-sessions';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

const { emitUserEvent, deleteSessionSideRecord } = vi.hoisted(() => ({
  emitUserEvent: vi.fn<(...args: unknown[]) => Promise<string>>(async () => 'event-id'),
  deleteSessionSideRecord: vi.fn(async () => undefined),
}));
// The helpers' modules read the environment at import; these rules read none of it.
vi.mock('../../config/env', () => ({ env: { NODE_ENV: 'test' } }));
vi.mock('./user-events', () => ({ emitUserEvent }));
vi.mock('./session-side-record', () => ({
  deleteSessionSideRecord,
  readSessionSideRecord: vi.fn(async () => ({})),
  writeSessionSideRecord: vi.fn(async () => undefined),
}));

import { createBrowserSessionFixture } from '../../testing/browser-sessions';
import { endAccountSession, endAllAccountSessions, pageAccountSessions } from './account-sessions';
import { InvalidCursorError } from './api-request-errors';

const REALM_ID = '00000000-0000-4000-8000-0000000000aa';
const OTHER_REALM_ID = '00000000-0000-4000-8000-0000000000bb';
const USER_ID = '00000000-0000-4000-8000-000000000001';
const OTHER_USER_ID = '00000000-0000-4000-8000-000000000002';
const REQUEST = { id: 'request-1' } as unknown as FastifyRequest;
const SIGNED_OUT = 'urn:qauth:event:user.signed_out:v1-rc.0';
const OWNER = { realmId: REALM_ID, userId: USER_ID, clientId: 'account-console' };

/** A server whose sessions are the fixture's, with the token repositories the changes call. */
function server() {
  const sessions = createBrowserSessionFixture();
  const repositories = {
    authorizationCodes: { invalidateForUser: vi.fn(async () => 0) },
    refreshTokens: {
      revokeAllForUser: vi.fn(async () => 0),
      revokeFamiliesOfSignIns: vi.fn(async () => 0),
    },
  };
  const fastify = {
    sessionService: sessions.service,
    repositories,
    log: { warn: vi.fn() },
  } as unknown as FastifyInstance;
  const signIn = (seed: { userId?: string; realmId?: string; authTime?: number }) =>
    sessions.service.seed({
      realmId: seed.realmId ?? REALM_ID,
      userId: seed.userId ?? USER_ID,
      ...(seed.authTime === undefined ? {} : { authTime: seed.authTime }),
    }).sid;
  return { fastify, sessions, repositories, signIn };
}

beforeEach(() => {
  emitUserEvent.mockClear();
  deleteSessionSideRecord.mockClear();
});

describe('pageAccountSessions (#1110)', () => {
  it('lists the account’s live sessions in its realm, marking the caller’s own', async () => {
    const { fastify, signIn } = server();
    const mine = signIn({});
    const other = signIn({});
    signIn({ userId: OTHER_USER_ID });
    signIn({ realmId: OTHER_REALM_ID });

    const page = await pageAccountSessions(fastify, OWNER, { limit: 10, currentSid: mine });

    expect(page.items.map((item) => [item.sid, item.current]).sort()).toEqual(
      [
        [mine, true],
        [other, false],
      ].sort()
    );
    expect(page.nextCursor).toBeNull();
  });

  it('marks no session without a current one, and passes the limit and cursor through', async () => {
    const { fastify, sessions, signIn } = server();
    signIn({});

    const page = await pageAccountSessions(fastify, OWNER, { limit: 7, cursor: 'abc' });

    expect(page.items.every((item) => !item.current)).toBe(true);
    expect(sessions.service.listLiveForUser).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      page: { limit: 7, cursor: 'abc' },
    });
  });

  it('answers a cursor the list did not issue with invalid_cursor, and passes other failures on', async () => {
    const { fastify, sessions } = server();
    sessions.service.listLiveForUser.mockRejectedValueOnce(new InvalidSessionCursorError());
    await expect(
      pageAccountSessions(fastify, OWNER, { limit: 1, cursor: 'x' })
    ).rejects.toBeInstanceOf(InvalidCursorError);

    const down = new Error('store down');
    sessions.service.listLiveForUser.mockRejectedValueOnce(down);
    await expect(pageAccountSessions(fastify, OWNER, { limit: 1 })).rejects.toBe(down);
  });
});

describe('endAccountSession (#1110)', () => {
  it('ends one session of the account, then the refresh families its sign-in opened, and records it with its sid', async () => {
    const { fastify, sessions, repositories, signIn } = server();
    const authTime = Date.now() - 60_000;
    const sid = signIn({ authTime });
    const kept = signIn({});

    expect(await endAccountSession(fastify, REQUEST, OWNER, sid)).toEqual({ kind: 'ended' });

    expect(sessions.service.sessions.has(sid)).toBe(false);
    expect(sessions.service.sessions.has(kept)).toBe(true);
    expect(sessions.service.revoke).toHaveBeenCalledWith({
      realmId: REALM_ID,
      sid,
      reason: 'sign_out',
      actor: { type: 'user', id: USER_ID },
      userId: USER_ID,
    });
    expect(deleteSessionSideRecord).toHaveBeenCalledWith(fastify, REALM_ID, sid);
    expect(repositories.refreshTokens.revokeFamiliesOfSignIns).toHaveBeenCalledWith(
      USER_ID,
      [authTime],
      'session_ended'
    );
    expect(repositories.refreshTokens.revokeAllForUser).not.toHaveBeenCalled();
    expect(emitUserEvent).toHaveBeenCalledTimes(1);
    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      SIGNED_OUT,
      { sid },
      {
        realmId: REALM_ID,
        userId: USER_ID,
        clientId: 'account-console',
        actor: 'user',
      }
    );
  });

  it('names the acting client of a delegated call', async () => {
    const { fastify, signIn } = server();
    const sid = signIn({});
    const act = { sub: 'agent-client' };

    await endAccountSession(fastify, REQUEST, { ...OWNER, act }, sid);

    expect(emitUserEvent).toHaveBeenCalledWith(
      REQUEST,
      SIGNED_OUT,
      { sid },
      expect.objectContaining({ act })
    );
  });

  it('answers another account’s session, another realm’s or an unknown one as not found, and touches nothing', async () => {
    const { fastify, sessions, repositories, signIn } = server();
    const theirs = signIn({ userId: OTHER_USER_ID });
    const elsewhere = signIn({ realmId: OTHER_REALM_ID });

    for (const sid of [theirs, elsewhere, '00000000-0000-4000-8000-0000000000ff']) {
      expect(await endAccountSession(fastify, REQUEST, OWNER, sid)).toEqual({
        kind: 'not_found',
      });
    }

    expect(sessions.service.sessions.has(theirs)).toBe(true);
    expect(sessions.service.sessions.has(elsewhere)).toBe(true);
    expect(repositories.refreshTokens.revokeFamiliesOfSignIns).not.toHaveBeenCalled();
    expect(deleteSessionSideRecord).not.toHaveBeenCalled();
    expect(emitUserEvent).not.toHaveBeenCalled();
  });

  it('answers an ended session of the account as not found, but sweeps its families again: the retry of an end whose sweep failed', async () => {
    const { fastify, repositories, signIn } = server();
    const authTime = Date.now() - 60_000;
    const sid = signIn({ authTime });
    repositories.refreshTokens.revokeFamiliesOfSignIns.mockRejectedValueOnce(new Error('pool'));
    await expect(endAccountSession(fastify, REQUEST, OWNER, sid)).rejects.toThrow('pool');
    expect(emitUserEvent).not.toHaveBeenCalled();

    expect(await endAccountSession(fastify, REQUEST, OWNER, sid)).toEqual({ kind: 'not_found' });

    expect(repositories.refreshTokens.revokeFamiliesOfSignIns).toHaveBeenCalledTimes(2);
    expect(repositories.refreshTokens.revokeFamiliesOfSignIns).toHaveBeenLastCalledWith(
      USER_ID,
      [authTime],
      'session_ended'
    );
    // The end already happened: no second sign-out is recorded for it.
    expect(emitUserEvent).not.toHaveBeenCalled();
  });
});

describe('endAllAccountSessions (#1110)', () => {
  it('ends every session of the account, then its codes and refresh families, and records one sign-out without a sid', async () => {
    const { fastify, sessions, repositories, signIn } = server();
    const one = signIn({});
    const two = signIn({});
    const theirs = signIn({ userId: OTHER_USER_ID });

    const ended = await endAllAccountSessions(fastify, REQUEST, OWNER);

    expect([...ended].sort()).toEqual([one, two].sort());
    expect(sessions.service.sessions.has(theirs)).toBe(true);
    expect(sessions.service.revokeAllForUser).toHaveBeenCalledWith({
      realmId: REALM_ID,
      userId: USER_ID,
      reason: 'sign_out_everywhere',
      actor: { type: 'user', id: USER_ID },
    });
    expect(repositories.authorizationCodes.invalidateForUser).toHaveBeenCalledWith(USER_ID);
    expect(repositories.refreshTokens.revokeAllForUser).toHaveBeenCalledWith(USER_ID, 'logout');
    // Codes first: one redeemed after the refresh sweep would survive it.
    expect(
      repositories.authorizationCodes.invalidateForUser.mock.invocationCallOrder[0]
    ).toBeLessThan(repositories.refreshTokens.revokeAllForUser.mock.invocationCallOrder[0]);
    expect(emitUserEvent).toHaveBeenCalledTimes(1);
    expect(emitUserEvent).toHaveBeenCalledWith(REQUEST, SIGNED_OUT, {}, expect.any(Object));
  });

  it('keeps the session asked for, and records one sign-out per session it ended', async () => {
    const { fastify, sessions, repositories, signIn } = server();
    const kept = signIn({});
    const one = signIn({});
    const two = signIn({});

    const ended = await endAllAccountSessions(fastify, REQUEST, OWNER, { keepSid: kept });

    expect([...ended].sort()).toEqual([one, two].sort());
    expect(sessions.service.sessions.has(kept)).toBe(true);
    expect(sessions.service.revokeAllForUser).toHaveBeenCalledWith(
      expect.objectContaining({ exceptSid: kept })
    );
    // Every refresh family still: a family names no session to keep.
    expect(repositories.refreshTokens.revokeAllForUser).toHaveBeenCalledWith(USER_ID, 'logout');
    const recorded = emitUserEvent.mock.calls.map((call) => call[2] as { sid?: string });
    expect(recorded.map((data) => data.sid).sort()).toEqual([one, two].sort());
    expect(recorded.every((data) => Object.keys(data).length === 1)).toBe(true);
  });

  it('keeps nothing when the session asked for has ended, and records one sign-out without a sid', async () => {
    const { fastify, sessions, signIn } = server();
    const gone = signIn({});
    await endAccountSession(fastify, REQUEST, OWNER, gone);
    const one = signIn({});
    const two = signIn({});
    emitUserEvent.mockClear();

    const ended = await endAllAccountSessions(fastify, REQUEST, OWNER, { keepSid: gone });

    expect([...ended].sort()).toEqual([one, two].sort());
    expect(sessions.service.sessions.size).toBe(0);
    expect(emitUserEvent).toHaveBeenCalledTimes(1);
    expect(emitUserEvent).toHaveBeenCalledWith(REQUEST, SIGNED_OUT, {}, expect.any(Object));
  });

  it('keeps nothing of another account’s session named as the one to keep', async () => {
    const { fastify, signIn } = server();
    const theirs = signIn({ userId: OTHER_USER_ID });
    signIn({});

    await endAllAccountSessions(fastify, REQUEST, OWNER, { keepSid: theirs });

    expect(emitUserEvent).toHaveBeenCalledTimes(1);
    expect(emitUserEvent).toHaveBeenCalledWith(REQUEST, SIGNED_OUT, {}, expect.any(Object));
  });
});
