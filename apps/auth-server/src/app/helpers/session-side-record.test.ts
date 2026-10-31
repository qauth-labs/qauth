import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// The fixture signs session cookies, which reads the cookie secret.
vi.mock('../../config/env', () => ({
  env: { SESSION_COOKIE_SECRET: 'test-secret-at-least-32-characters-long-padding' },
}));

import { createMemorySessionRedis, type MemorySessionRedis } from '../../testing/browser-sessions';
import {
  burnConsentCsrfToken,
  deleteSessionSideRecord,
  readSessionSideRecord,
  writeSessionSideRecord,
} from './session-side-record';

const SESSION = {
  realmId: '22222222-2222-4222-8222-222222222222',
  sid: '0190a5c8-0000-7000-8000-00000000000a',
  expiresAt: Date.now() + 3_600_000,
};
const KEY = `browser-session-side:${SESSION.realmId}:${SESSION.sid}`;

let redis: MemorySessionRedis;
let fastify: FastifyInstance;

beforeEach(() => {
  redis = createMemorySessionRedis();
  fastify = { redis } as unknown as FastifyInstance;
});

describe('session side record', () => {
  it('reads an absent record as an empty one', async () => {
    await expect(readSessionSideRecord(fastify, SESSION)).resolves.toEqual({
      consentScopes: {},
      consentResources: {},
      consentAgent: {},
    });
  });

  it('keeps each value in its own field, keyed by the realm and the sid', async () => {
    await writeSessionSideRecord(fastify, SESSION, { identifier: 'alice@example.com' });
    await writeSessionSideRecord(fastify, SESSION, {
      csrfToken: 'consent-token',
      consent: { clientId: 'app-1', scopes: ['openid', 'email'], resources: [], agent: false },
    });
    await writeSessionSideRecord(fastify, SESSION, { apiCsrfToken: 'api-token' });
    await writeSessionSideRecord(fastify, SESSION, {
      consent: {
        clientId: 'app-2',
        scopes: ['read:foo'],
        resources: ['https://api.example'],
        agent: true,
      },
    });

    // A later write sets only what it names: the consent screen and the
    // consent API never overwrite each other's token.
    await expect(readSessionSideRecord(fastify, SESSION)).resolves.toEqual({
      identifier: 'alice@example.com',
      csrfToken: 'consent-token',
      apiCsrfToken: 'api-token',
      consentScopes: { 'app-1': ['openid', 'email'], 'app-2': ['read:foo'] },
      consentResources: { 'app-1': [], 'app-2': ['https://api.example'] },
      consentAgent: { 'app-1': false, 'app-2': true },
    });
    expect([...(redis.hashes.get(KEY)?.keys() ?? [])].sort()).toEqual([
      'apiCsrfToken',
      'consentAgent:app-1',
      'consentAgent:app-2',
      'consentResources:app-1',
      'consentResources:app-2',
      'consentScopes:app-1',
      'consentScopes:app-2',
      'csrfToken',
      'identifier',
    ]);
  });

  it('expires with the session absolute end on every write, never later', async () => {
    await writeSessionSideRecord(fastify, SESSION, { csrfToken: 'a' });
    expect(redis.expiries.get(KEY)).toBe(SESSION.expiresAt);

    await writeSessionSideRecord(
      fastify,
      { ...SESSION, expiresAt: SESSION.expiresAt },
      {
        apiCsrfToken: 'b',
      }
    );
    expect(redis.expiries.get(KEY)).toBe(SESSION.expiresAt);
  });

  it('sends nothing for an empty update', async () => {
    await writeSessionSideRecord(fastify, SESSION, {});

    expect(redis.multi).not.toHaveBeenCalled();
  });

  it('rebinds a client to the scopes of the latest screen', async () => {
    await writeSessionSideRecord(fastify, SESSION, {
      consent: {
        clientId: 'app-1',
        scopes: ['read:foo', 'write:foo'],
        resources: [],
        agent: false,
      },
    });
    await writeSessionSideRecord(fastify, SESSION, {
      consent: { clientId: 'app-1', scopes: ['read:foo'], resources: [], agent: false },
    });

    const side = await readSessionSideRecord(fastify, SESSION);
    expect(side.consentScopes['app-1']).toEqual(['read:foo']);
  });

  it('never binds a consent from a field that does not parse', async () => {
    redis.hashes.set(
      KEY,
      new Map([
        ['consentScopes:app-1', 'not json'],
        ['consentScopes:app-2', '{"scope":"admin"}'],
        ['consentResources:app-3', '[1,2]'],
        ['consentAgent:app-4', 'true'],
        ['somethingElse', 'x'],
      ])
    );

    await expect(readSessionSideRecord(fastify, SESSION)).resolves.toEqual({
      consentScopes: {},
      consentResources: {},
      consentAgent: {},
    });
  });

  it('burns the consent CSRF token and keeps the rest', async () => {
    await writeSessionSideRecord(fastify, SESSION, { csrfToken: 'a', apiCsrfToken: 'b' });

    await burnConsentCsrfToken(fastify, SESSION);

    const side = await readSessionSideRecord(fastify, SESSION);
    expect(side.csrfToken).toBeUndefined();
    expect(side.apiCsrfToken).toBe('b');
  });

  it('deletes the whole record', async () => {
    await writeSessionSideRecord(fastify, SESSION, { csrfToken: 'a' });

    await deleteSessionSideRecord(fastify, SESSION.realmId, SESSION.sid);

    expect(redis.hashes.has(KEY)).toBe(false);
  });

  it('fails a write whose MULTI reports a failed command', async () => {
    redis.multi.mockReturnValueOnce({
      hset() {
        return this;
      },
      sadd() {
        return this;
      },
      pexpireat() {
        return this;
      },
      exec: vi.fn().mockResolvedValue([[new Error('WRONGTYPE'), null]]),
    } as never);

    await expect(writeSessionSideRecord(fastify, SESSION, { csrfToken: 'a' })).rejects.toThrow(
      'WRONGTYPE'
    );
  });
});
