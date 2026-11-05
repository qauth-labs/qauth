import type { RoundLimitPolicy, RoundLimitStore } from '@qauth-labs/fastify-plugin-sign-in-engine';
import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: { NODE_ENV: 'test', REGISTRATION_RATE_LIMIT: 2, REGISTRATION_RATE_WINDOW: 600 },
}));

const redisStores = vi.hoisted(() => ({ options: [] as unknown[] }));
vi.mock('@qauth-labs/fastify-plugin-sign-in-engine', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@qauth-labs/fastify-plugin-sign-in-engine')>();
  return {
    ...actual,
    // A store that counts registration starts against the policy the server
    // built, and blocks the IP at a failure: the Redis store's own rules are
    // its contract's (`round-limit-store-contract.ts`).
    createRedisRoundLimits: vi.fn((_redis: unknown, options: { policy: RoundLimitPolicy }) => {
      redisStores.options.push(options);
      let starts = 0;
      const store: RoundLimitStore = {
        admitRound: async () => ({ kind: 'admitted', alerts: [] }),
        reserveCredential: async () => ({ kind: 'admitted', alerts: [] }),
        settleCredential: async (round) =>
          round.outcome === 'failure' ? ['end_user_ip_blocked'] : [],
        reserveRegistrationStart: async () => {
          const { limit, windowMs } = options.policy.registrationStarts.endUserIp;
          if (starts >= limit) {
            return {
              kind: 'refused',
              limit: 'registration_end_user_ip',
              retryAfterMs: windowMs,
              alerts: [],
            };
          }
          starts += 1;
          return { kind: 'admitted', alerts: [] };
        },
      };
      return store;
    }),
  };
});

vi.mock('./password-attempts', () => ({
  createServerDigests: vi.fn(() => ({
    identifierDigest: async ({ identifier }: { identifier: string }) => `id-${identifier.length}`,
    ipDigest: async ({ identifier }: { identifier: string }) =>
      `ip-${Buffer.from(identifier).toString('base64url')}`.slice(0, 64),
  })),
}));

import {
  createServerRoundLimiter,
  logRoundLimitAlert,
  ROUND_LIMIT_ALERT,
  roundEnvironment,
} from './round-limits';

const REALM = '0199fa20-0000-7000-8000-00000000aaaa';

function server(clients: Record<string, { environment: string } | Error> = {}) {
  const findByClientId = vi.fn(async (_realmId: string, clientId: string) => {
    const client = clients[clientId];
    if (client instanceof Error) throw client;
    return client;
  });
  const log = { error: vi.fn(), warn: vi.fn() };
  const fastify = {
    redis: {},
    log,
    repositories: { oauthClients: { findByClientId } },
  } as unknown as FastifyInstance;
  return { fastify, findByClientId, log };
}

const realm = (maxEnvironmentLaxity: string | null) =>
  ({ id: REALM, maxEnvironmentLaxity }) as Parameters<typeof roundEnvironment>[1];

beforeEach(() => {
  redisStores.options.length = 0;
});

describe('the round limits’ environment (ADR-008 §5)', () => {
  it('is production in a production realm, and reads no client there', async () => {
    const { fastify, findByClientId } = server({ dev: { environment: 'development' } });
    expect(await roundEnvironment(fastify, realm('production'), 'dev')).toBe('production');
    expect(await roundEnvironment(fastify, realm(null), 'dev')).toBe('production');
    expect(findByClientId).not.toHaveBeenCalled();
  });

  it('is the stricter of the client’s and the realm’s ceiling', async () => {
    const { fastify } = server({
      dev: { environment: 'development' },
      stage: { environment: 'staging' },
      prod: { environment: 'production' },
    });
    expect(await roundEnvironment(fastify, realm('development'), 'dev')).toBe('development');
    expect(await roundEnvironment(fastify, realm('development'), 'stage')).toBe('staging');
    expect(await roundEnvironment(fastify, realm('development'), 'prod')).toBe('production');
    expect(await roundEnvironment(fastify, realm('staging'), 'dev')).toBe('staging');
  });

  it('is production for a client it cannot find or read', async () => {
    const { fastify, log } = server({ broken: new Error('database down') });
    expect(await roundEnvironment(fastify, realm('development'), 'unknown')).toBe('production');
    expect(await roundEnvironment(fastify, realm('development'), 'broken')).toBe('production');
    expect(log.warn).toHaveBeenCalledTimes(1);
  });
});

describe('the server’s round limiter', () => {
  it('caps registration starts per IP at REGISTRATION_RATE_LIMIT per REGISTRATION_RATE_WINDOW', async () => {
    const { fastify } = server();
    const limiter = createServerRoundLimiter(fastify, { perClient: false });
    expect(redisStores.options).toMatchObject([
      { policy: { registrationStarts: { endUserIp: { limit: 2, windowMs: 600_000 } } } },
    ]);
    const start = { realmId: REALM, clientId: 'app', endUserIp: '203.0.113.7' };
    expect(await limiter.reserveRegistrationStart(start)).toEqual({ kind: 'continue' });
    expect(await limiter.reserveRegistrationStart(start)).toEqual({ kind: 'continue' });
    expect(await limiter.reserveRegistrationStart(start)).toEqual({
      kind: 'throttled',
      retryAfterSeconds: 600,
    });
  });

  it('tells the operator at error when an IP is blocked, by its HMAC and never its address', async () => {
    const { fastify, log } = server();
    const limiter = createServerRoundLimiter(fastify, { perClient: false });
    const reservation = await limiter.reserve({
      realmId: REALM,
      clientId: 'app',
      endUserIp: '203.0.113.7',
      environment: 'production',
    });
    if (reservation.kind !== 'reserved') throw new Error('refused');
    await reservation.settle('failure');
    expect(log.error).toHaveBeenCalledWith(
      {
        realmId: REALM,
        alert: 'end_user_ip_blocked',
        endUserIpHmac: `ip-${Buffer.from('203.0.113.7').toString('base64url')}`,
      },
      ROUND_LIMIT_ALERT
    );
    expect(JSON.stringify(log.error.mock.calls)).not.toContain('203.0.113.7');
  });

  it('logs every alert with the realm, the alert and its key', async () => {
    const { fastify, log } = server();
    logRoundLimitAlert(fastify.log, {
      realmId: REALM,
      alert: 'end_user_ip_blocked',
      endUserIpHmac: 'ip-hmac',
    });
    expect(log.error).toHaveBeenCalledWith(
      { realmId: REALM, alert: 'end_user_ip_blocked', endUserIpHmac: 'ip-hmac' },
      ROUND_LIMIT_ALERT
    );
  });
});
