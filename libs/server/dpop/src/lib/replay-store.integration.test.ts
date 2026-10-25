import {
  requireDockerOrSkip,
  type StartedRedis,
  startRedisContainer,
} from '@qauth-labs/shared-testing';
import Redis from 'ioredis';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

import { signProof, TEST_METHOD, TEST_URL, type TestKey, testKey } from '../testing/proofs';
import { DpopProofError } from './dpop-error';
import { createRedisDpopReplayStore, DEFAULT_DPOP_REPLAY_KEY_PREFIX } from './replay-store';
import { createDpopVerifier, DEFAULT_DPOP_REPLAY_STORE_TIMEOUT_MS } from './verifier';

/**
 * The replay store on a real Redis (RFC 9449 §11.1, issue #479), through the
 * `ioredis` client the deployment uses: a used proof is refused, two racing
 * uses let exactly one through, and with Redis gone every proof is refused
 * within the store's time limit.
 *
 * Requires Docker (testcontainers); skips without it, except on CI
 * (`requireDockerOrSkip`).
 */

const nowSeconds = () => Math.floor(Date.now() / 1000);

function check(proof: string) {
  return { proof, method: TEST_METHOD, url: TEST_URL };
}

async function reasonOf(promise: Promise<unknown>): Promise<string | undefined> {
  try {
    await promise;
    return undefined;
  } catch (error) {
    if (!(error instanceof DpopProofError)) throw error;
    return error.reason;
  }
}

describe('the DPoP replay store on a real Redis', () => {
  let dockerUp = false;
  let redis: StartedRedis | undefined;
  let client: Redis | undefined;
  let key: TestKey;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    [redis, key] = await Promise.all([startRedisContainer(), testKey('ES256')]);
    client = new Redis(redis.connectionUrl);
  }, 180_000);

  afterAll(async () => {
    client?.disconnect();
    await redis?.stop();
  });

  it('accepts a proof once, refuses it after, and keeps it for three windows and a second', async (ctx) => {
    if (!dockerUp || !client) return ctx.skip();
    const dpop = createDpopVerifier({ replayStore: createRedisDpopReplayStore(client) });
    const proof = await signProof({ key, iat: nowSeconds() });

    await expect(dpop.verify(check(proof))).resolves.toBeDefined();
    expect(await reasonOf(dpop.verify(check(proof)))).toBe('replayed');

    const keys = await client.keys(`${DEFAULT_DPOP_REPLAY_KEY_PREFIX}*`);
    expect(keys).toHaveLength(1);
    const ttl = await client.pttl(keys[0]);
    expect(ttl).toBeGreaterThan(170_000);
    expect(ttl).toBeLessThanOrEqual(181_000);
  });

  it('lets exactly one of several racing uses of one proof through', async (ctx) => {
    if (!dockerUp || !client) return ctx.skip();
    const dpop = createDpopVerifier({ replayStore: createRedisDpopReplayStore(client) });
    const proof = await signProof({ key, iat: nowSeconds() });

    const reasons = await Promise.all(
      Array.from({ length: 10 }, () => reasonOf(dpop.verify(check(proof))))
    );

    expect(reasons.filter((reason) => reason === undefined)).toHaveLength(1);
    expect(reasons.filter((reason) => reason === 'replayed')).toHaveLength(9);
  });
});

describe('the DPoP replay store with Redis gone', () => {
  let dockerUp = false;
  let redis: StartedRedis | undefined;
  let client: Redis | undefined;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    redis = await startRedisContainer();
    client = new Redis(redis.connectionUrl);
  }, 180_000);

  afterAll(() => {
    client?.disconnect();
  });

  it('refuses every proof, each within the time limit, once Redis stops', async (ctx) => {
    if (!dockerUp || !client || !redis) return ctx.skip();
    const dpop = createDpopVerifier({ replayStore: createRedisDpopReplayStore(client) });
    const key = await testKey('EdDSA');
    await expect(
      dpop.verify(check(await signProof({ key, iat: nowSeconds() })))
    ).resolves.toBeDefined();

    await redis.stop();

    const proofs = await Promise.all(
      Array.from({ length: 5 }, () => signProof({ key, iat: nowSeconds() }))
    );
    for (const proof of proofs) {
      const started = Date.now();
      expect(await reasonOf(dpop.verify(check(proof)))).toBe('replay-store-unavailable');
      expect(Date.now() - started).toBeLessThan(DEFAULT_DPOP_REPLAY_STORE_TIMEOUT_MS + 1_000);
    }
  });

  it('refuses every proof when Redis was never there', async (ctx) => {
    if (!dockerUp) return ctx.skip();
    // A port nothing listens on: the client keeps reconnecting and queues the command.
    const absent = new Redis({ host: '127.0.0.1', port: 1, lazyConnect: false });
    absent.on('error', () => undefined);
    try {
      const dpop = createDpopVerifier({ replayStore: createRedisDpopReplayStore(absent) });
      const key = await testKey('ES256');
      for (let i = 0; i < 3; i += 1) {
        const proof = await signProof({ key, iat: nowSeconds() });
        expect(await reasonOf(dpop.verify(check(proof)))).toBe('replay-store-unavailable');
      }
    } finally {
      absent.disconnect();
    }
  });
});
