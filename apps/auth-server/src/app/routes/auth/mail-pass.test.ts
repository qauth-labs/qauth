import { createRedisSendCaps, mailPassHash } from '@qauth-labs/fastify-plugin-sign-in-engine';
import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const started = vi.hoisted(() => ({ calls: [] as unknown[] }));
vi.mock('../../helpers/interaction', () => ({
  startMailedPassInteraction: vi.fn(async (_request: unknown, _reply: unknown, input: unknown) => {
    started.calls.push(input);
    return { id: 'I'.repeat(43), expiresAt: 0 };
  }),
}));

import { supplyRequestRealm, testRealm } from '../../../testing/request-realm';
import mailPassRoutes from './mail-pass';

const REALM_ID = '9a1f6a1e-5a5b-4c1a-9a7e-3d1c1c2b0a01';

/** A Redis double for the send-cap store's pass keys. */
function passRedis() {
  const values = new Map<string, string>();
  return {
    values,
    evalsha: vi.fn(),
    eval: vi.fn(),
    get: vi.fn(async (key: string) => values.get(key) ?? null),
    set: vi.fn(async (key: string, value: string) => {
      values.set(key, value);
      return 'OK' as const;
    }),
  };
}

/**
 * GET /auth/pass — the link of a send-ceiling or password-disabled notice
 * (#637). Opening it starts an interaction that holds the pass, and never
 * spends it.
 */
describe('GET /auth/pass (a mailed pass link)', () => {
  let app: FastifyInstance;
  let redis: ReturnType<typeof passRedis>;

  beforeEach(async () => {
    started.calls.length = 0;
    redis = passRedis();
    app = Fastify();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    app.decorate('redis', redis as never);
    supplyRequestRealm(app, testRealm({ id: REALM_ID }));
    await app.register(mailPassRoutes, { prefix: '/auth' });
    await app.ready();
  });

  afterEach(async () => {
    await app.close();
  });

  const mint = (flow: 'reset' | 'register') =>
    createRedisSendCaps(redis).mintPass({ realmId: REALM_ID, addressHmac: 'address-hmac', flow });

  it.each([
    ['reset', 'password_reset'],
    ['register', 'identifier'],
  ] as const)(
    'starts a %s interaction that holds the pass’s hash and redirects with its id alone',
    async (flow, step) => {
      const pass = await mint(flow);

      const res = await app.inject({ method: 'GET', url: `/auth/pass?pass=${pass}` });

      expect(res.statusCode).toBe(303);
      expect(res.headers.location).toBe(`/ui/interaction/${'I'.repeat(43)}`);
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(started.calls).toEqual([
        {
          request: { flow, passHash: mailPassHash(pass) },
          step: { name: stepUrn(step), params: {}, alternatives: [] },
        },
      ]);
      expect(JSON.stringify(started.calls)).not.toContain(pass);
    }
  );

  it('never spends the pass: opening the link twice opens it twice', async () => {
    const pass = await mint('reset');

    for (let i = 0; i < 2; i++) {
      const res = await app.inject({ method: 'GET', url: `/auth/pass?pass=${pass}` });
      expect(res.statusCode).toBe(303);
    }
    expect(started.calls).toHaveLength(2);
    expect(redis.values.size).toBe(1);
  });

  it.each([
    ['no pass', '/auth/pass'],
    ['a malformed pass', '/auth/pass?pass=short'],
    ['an unknown pass', `/auth/pass?pass=${'u'.repeat(43)}`],
  ])('answers %s with one page and starts nothing', async (_label, url) => {
    const res = await app.inject({ method: 'GET', url });

    expect(res.statusCode).toBe(400);
    expect(res.headers['content-type']).toBe('text/html; charset=utf-8');
    expect(res.headers['cache-control']).toBe('no-store');
    expect(res.body).toContain('This link is no longer valid');
    expect(res.body).not.toContain('short');
    expect(started.calls).toEqual([]);
  });
});
