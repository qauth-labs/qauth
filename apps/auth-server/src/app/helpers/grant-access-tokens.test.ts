import type { FastifyInstance } from 'fastify';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { recordGrantAccessToken, revokeGrantAccessTokens } from './grant-access-tokens';

/**
 * The access tokens a grant issued (#627, ADR-017 Decision 10): recorded at
 * issuance against the code and the refresh family, denylisted on a replay.
 */

const CODE_ID = '0199f2b4-7c3e-7a51-9d2b-3a6c8e1f0a41';
const FAMILY_ID = '0199f2b4-7c3e-7a51-9d2b-3a6c8e1f0a42';
const CODE_KEY = `code-access-tokens:${CODE_ID}`;
const FAMILY_KEY = `refresh-family-access-tokens:${FAMILY_ID}`;
const NOW_MS = 1_800_000_000_000;
const NOW = NOW_MS / 1000;

/**
 * An in-memory Redis with the semantics the helpers rely on: hashes, `EXPIRE`
 * with `NX` and `GT` (a key without an expiry counts as infinite for `GT`, as
 * in Redis 7), `MULTI`/`EXEC` and `SETEX`.
 */
function fakeRedis() {
  const hashes = new Map<string, Map<string, string>>();
  const expiries = new Map<string, number>();
  const denylist = new Map<string, number>();
  const multi = () => {
    const ops: (() => unknown)[] = [];
    const chain = {
      hset(key: string, field: string, value: string) {
        ops.push(() => {
          const hash = hashes.get(key) ?? new Map<string, string>();
          hash.set(field, value);
          hashes.set(key, hash);
          return 1;
        });
        return chain;
      },
      expire(key: string, seconds: number, mode: 'NX' | 'GT') {
        ops.push(() => {
          const current = expiries.get(key);
          if (mode === 'NX' && current !== undefined) return 0;
          if (mode === 'GT' && (current === undefined || seconds <= current)) return 0;
          expiries.set(key, seconds);
          return 1;
        });
        return chain;
      },
      exec: async () => ops.map((op) => [null, op()]),
    };
    return chain;
  };
  return {
    hashes,
    expiries,
    denylist,
    client: {
      multi: vi.fn(multi),
      hgetall: vi.fn(async (key: string) => Object.fromEntries(hashes.get(key) ?? [])),
      setex: vi.fn(async (key: string, ttl: number, _value: string) => {
        denylist.set(key, ttl);
        return 'OK';
      }),
    },
  };
}

function setup() {
  const redis = fakeRedis();
  const claims = new Map<string, { jti?: string; exp?: number }>();
  const fastify = {
    redis: redis.client,
    jwtUtils: { decodeTokenUnsafe: vi.fn((token: string) => claims.get(token) ?? {}) },
    log: { warn: vi.fn(), error: vi.fn() },
  } as unknown as FastifyInstance;
  /** A signed token with this `jti`, expiring `lifetime` seconds from now. */
  const token = (jti: string, lifetime: number) => {
    claims.set(jti, { jti, exp: NOW + lifetime });
    return jti;
  };
  return { fastify, redis, token, claims };
}

beforeEach(() => {
  vi.useFakeTimers({ now: NOW_MS, toFake: ['Date'] });
});

afterEach(() => {
  vi.useRealTimers();
});

describe('recordGrantAccessToken', () => {
  it('records the token under the code and the family, each expiring with the token', async () => {
    const { fastify, redis, token } = setup();

    await recordGrantAccessToken(fastify, token('jti-1', 900), {
      authorizationCodeId: CODE_ID,
      refreshFamilyId: FAMILY_ID,
    });

    expect(Object.fromEntries(redis.hashes.get(CODE_KEY) ?? [])).toEqual({
      'jti-1': String(NOW + 900),
    });
    expect(Object.fromEntries(redis.hashes.get(FAMILY_KEY) ?? [])).toEqual({
      'jti-1': String(NOW + 900),
    });
    expect(redis.expiries.get(CODE_KEY)).toBe(900);
    expect(redis.expiries.get(FAMILY_KEY)).toBe(900);
  });

  it('lengthens the record for a later token and never shortens it', async () => {
    const { fastify, redis, token } = setup();
    const family = { refreshFamilyId: FAMILY_ID };

    await recordGrantAccessToken(fastify, token('jti-1', 900), family);
    await recordGrantAccessToken(fastify, token('jti-2', 1800), family);
    await recordGrantAccessToken(fastify, token('jti-3', 60), family);

    expect([...(redis.hashes.get(FAMILY_KEY)?.keys() ?? [])]).toEqual(['jti-1', 'jti-2', 'jti-3']);
    expect(redis.expiries.get(FAMILY_KEY)).toBe(1800);
  });

  it('records nothing for a grant it cannot name', async () => {
    const { fastify, redis, token } = setup();

    await recordGrantAccessToken(fastify, token('jti-1', 900), { refreshFamilyId: null });

    expect(redis.client.multi).not.toHaveBeenCalled();
  });

  it('logs and goes on when Redis fails, so issuance does not depend on it', async () => {
    const { fastify, redis, token } = setup();
    redis.client.multi.mockImplementationOnce(() => {
      throw new Error('connection refused');
    });

    await expect(
      recordGrantAccessToken(fastify, token('jti-1', 900), { authorizationCodeId: CODE_ID })
    ).resolves.toBeUndefined();
    expect(fastify.log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ authorizationCodeId: CODE_ID }),
      expect.stringContaining('will not revoke it')
    );
  });

  it('logs a command the transaction refused', async () => {
    const { fastify, redis, token } = setup();
    redis.client.multi.mockImplementationOnce(() => {
      const chain = {
        hset: () => chain,
        expire: () => chain,
        exec: async () => [[new Error('WRONGTYPE'), null]],
      };
      return chain as never;
    });

    await recordGrantAccessToken(fastify, token('jti-1', 900), { authorizationCodeId: CODE_ID });

    expect(fastify.log.warn).toHaveBeenCalledTimes(1);
  });

  it('logs a token without a jti instead of recording it', async () => {
    const { fastify, redis, claims } = setup();
    claims.set('no-jti', { exp: NOW + 900 });

    await recordGrantAccessToken(fastify, 'no-jti', { authorizationCodeId: CODE_ID });

    expect(redis.hashes.size).toBe(0);
    expect(fastify.log.warn).toHaveBeenCalledTimes(1);
  });
});

describe('revokeGrantAccessTokens', () => {
  it('denylists every unexpired token of the code and the family, each for its remaining life', async () => {
    const { fastify, redis, token } = setup();
    // The redemption's token is in both records; a rotation's in the family's.
    await recordGrantAccessToken(fastify, token('jti-code', 900), {
      authorizationCodeId: CODE_ID,
      refreshFamilyId: FAMILY_ID,
    });
    await recordGrantAccessToken(fastify, token('jti-rotated', 1200), {
      refreshFamilyId: FAMILY_ID,
    });
    redis.hashes.get(FAMILY_KEY)?.set('jti-expired', String(NOW - 1));

    const revoked = await revokeGrantAccessTokens(fastify, {
      authorizationCodeId: CODE_ID,
      refreshFamilyId: FAMILY_ID,
    });

    expect(revoked).toBe(2);
    expect(Object.fromEntries(redis.denylist)).toEqual({
      'revoked-access-token:jti-code': 900,
      'revoked-access-token:jti-rotated': 1200,
    });
  });

  it('revokes nothing, and says so, for a grant with no recorded token', async () => {
    const { fastify, redis } = setup();

    expect(await revokeGrantAccessTokens(fastify, { authorizationCodeId: CODE_ID })).toBe(0);
    expect(redis.denylist.size).toBe(0);
  });

  it('answers undefined and logs an error when Redis fails, never a count', async () => {
    const { fastify, redis, token } = setup();
    await recordGrantAccessToken(fastify, token('jti-1', 900), { refreshFamilyId: FAMILY_ID });
    redis.client.setex.mockRejectedValueOnce(new Error('connection refused'));

    expect(await revokeGrantAccessTokens(fastify, { refreshFamilyId: FAMILY_ID })).toBeUndefined();
    expect(fastify.log.error).toHaveBeenCalledWith(
      expect.objectContaining({ refreshFamilyId: FAMILY_ID }),
      expect.stringContaining('stay valid until they expire')
    );
  });
});
