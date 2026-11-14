import { describe, expect, it } from 'vitest';

import { createPeerRateLimit } from './peer-rate-limit';

describe('createPeerRateLimit (#497)', () => {
  it('lets a peer spend its burst, then its rate, and tells how long to wait', () => {
    let now = 1_000_000;
    const limit = createPeerRateLimit({ ratePerSecond: 10, burst: 3, now: () => now });
    for (let index = 0; index < 3; index += 1) {
      expect(limit.take('peer-a')).toEqual({ allowed: true });
    }
    const refused = limit.take('peer-a');
    expect(refused).toMatchObject({ allowed: false, retryAfterMs: 100 });

    // A tenth of a second gives one call back.
    now += 100;
    expect(limit.take('peer-a')).toEqual({ allowed: true });
    expect(limit.take('peer-a').allowed).toBe(false);
    // The bucket never holds more than the burst.
    now += 60_000;
    for (let index = 0; index < 3; index += 1) expect(limit.take('peer-a').allowed).toBe(true);
    expect(limit.take('peer-a').allowed).toBe(false);
  });

  it('keeps a bucket per peer', () => {
    const limit = createPeerRateLimit({ ratePerSecond: 1, burst: 1, now: () => 0 });
    expect(limit.take('peer-a').allowed).toBe(true);
    expect(limit.take('peer-a').allowed).toBe(false);
    expect(limit.take('peer-b').allowed).toBe(true);
  });

  it('logs one refusal a minute per peer, with how many it stands for', () => {
    let now = 0;
    const limit = createPeerRateLimit({ ratePerSecond: 0.001, burst: 1, now: () => now });
    limit.take('peer-a');
    expect(limit.take('peer-a')).toMatchObject({ allowed: false, logSuppressed: 0 });
    expect(limit.take('peer-a')).toMatchObject({ allowed: false, logSuppressed: undefined });
    expect(limit.take('peer-a')).toMatchObject({ allowed: false, logSuppressed: undefined });
    now += 60_000;
    expect(limit.take('peer-a')).toMatchObject({ allowed: false, logSuppressed: 2 });
  });

  it('forgets the peer seen longest ago past its cap, which starts again full', () => {
    const limit = createPeerRateLimit({ ratePerSecond: 1, burst: 1, maxPeers: 2, now: () => 0 });
    limit.take('peer-a');
    limit.take('peer-b');
    // peer-a was seen last: peer-b is forgotten when peer-c arrives.
    expect(limit.take('peer-a').allowed).toBe(false);
    limit.take('peer-c');
    expect(limit.take('peer-a').allowed).toBe(false);
    expect(limit.take('peer-b').allowed).toBe(true);
  });

  it('refuses a rate or a burst that is not positive', () => {
    expect(() => createPeerRateLimit({ ratePerSecond: 0, burst: 1 })).toThrow(TypeError);
    expect(() => createPeerRateLimit({ ratePerSecond: 1, burst: 0 })).toThrow(TypeError);
  });
});
