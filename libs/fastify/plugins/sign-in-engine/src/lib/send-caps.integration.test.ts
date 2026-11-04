/**
 * The send caps (#637, ADR-017 Decision 5) over real Redis: the Lua script
 * itself, held to the same contract the memory store keeps
 * (`@qauth-labs/server-sign-in-engine`'s `send-cap-store-contract.ts`). Each
 * case works in a realm of its own; the store runs on a clock the case moves.
 *
 * Requires Docker; skips locally without it, fails on CI (requireDockerOrSkip).
 */
import { type CacheClient, createRedisConnection } from '@qauth-labs/infra-cache';
import { describeSendCapStore } from '@qauth-labs/server-sign-in-engine/src/testing/send-cap-store-contract';
import {
  requireDockerOrSkip,
  type StartedRedis,
  startRedisContainer,
} from '@qauth-labs/shared-testing';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { createRedisSendCaps, sendCapKey } from './send-caps';

const silent = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

let dockerUp = false;
let container: StartedRedis | undefined;
let redis: CacheClient | undefined;

beforeAll(async () => {
  dockerUp = await requireDockerOrSkip();
  if (!dockerUp) return;
  container = await startRedisContainer();
  redis = createRedisConnection({ url: container.connectionUrl, logger: silent });
}, 180_000);

afterAll(async () => {
  redis?.disconnect();
  await container?.stop();
});

describeSendCapStore('the Redis store', async () => {
  if (!dockerUp || redis === undefined) return undefined;
  let clock = Date.UTC(2026, 10, 4);
  return {
    store: createRedisSendCaps(redis, { now: () => clock }),
    advance: (ms: number) => {
      clock += ms;
    },
  };
});

describe('the Redis send caps’ keys', () => {
  it('hold no address, keep a realm’s keys in one slot, and expire', async (context) => {
    if (!dockerUp || redis === undefined) return context.skip();
    const realmId = '9a1f6a1e-5a5b-4c1a-9a7e-3d1c1c2b0a01';
    const store = createRedisSendCaps(redis);
    await store.reserve({
      realmId,
      addressHmac: 'address-hmac',
      endUserIpHmac: 'ip-hmac',
      clientKey: 'client-id',
      knownIp: false,
      afterFirstFactor: false,
    });

    const keys = await redis.keys(`send-caps:{${realmId}}:*`);
    const kinds = keys.map((key) => key.slice(`send-caps:{${realmId}}:`.length).split(':')[0]);
    expect(kinds.sort()).toEqual(['address-client', 'address-ip', 'ceiling', 'client', 'ip']);
    expect(keys).toContain(sendCapKey(realmId, 'address-ip', 'address-hmac', 'ip-hmac'));
    // A client is keyed by a hash of its id, never the id.
    expect(keys.join(' ')).not.toContain('client-id');
    for (const key of keys) {
      expect(await redis.pttl(key)).toBeGreaterThan(0);
    }
  });
});
