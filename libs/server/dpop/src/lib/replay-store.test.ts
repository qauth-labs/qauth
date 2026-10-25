import { describe, expect, it, vi } from 'vitest';

import {
  createRedisDpopReplayStore,
  DEFAULT_DPOP_REPLAY_KEY_PREFIX,
  type DpopRedisClient,
} from './replay-store';

/** The Redis replay store: one `SET … PX … NX` per proof (RFC 9449 §11.1). */

function client(reply: 'OK' | null | Error | string) {
  return {
    set: vi.fn<DpopRedisClient['set']>(async () => {
      if (reply instanceof Error) throw reply;
      return reply as 'OK' | null;
    }),
  };
}

describe('createRedisDpopReplayStore', () => {
  it('sends one SET with PX and NX under its prefix, and reads OK as a first use', async () => {
    const redis = client('OK');

    await expect(createRedisDpopReplayStore(redis).record('hash', 121_000)).resolves.toBe(true);
    expect(redis.set.mock.calls).toEqual([
      [`${DEFAULT_DPOP_REPLAY_KEY_PREFIX}hash`, '1', 'PX', 121_000, 'NX'],
    ]);
  });

  it('reads a nil reply as a replay', async () => {
    await expect(createRedisDpopReplayStore(client(null)).record('hash', 1_000)).resolves.toBe(
      false
    );
  });

  it('rejects on a failed command or a reply SET NX never gives', async () => {
    await expect(
      createRedisDpopReplayStore(client(new Error('ECONNREFUSED'))).record('hash', 1_000)
    ).rejects.toThrow('ECONNREFUSED');
    await expect(
      createRedisDpopReplayStore(client('QUEUED')).record('hash', 1_000)
    ).rejects.toThrow('a reply SET NX does not give');
  });

  it('takes another prefix, and rounds the TTL up to a whole positive millisecond', async () => {
    const redis = client('OK');
    const store = createRedisDpopReplayStore(redis, { keyPrefix: 'rs:dpop:' });

    await store.record('hash', 0.2);
    expect(redis.set.mock.calls[0]).toEqual(['rs:dpop:hash', '1', 'PX', 1, 'NX']);
  });
});
