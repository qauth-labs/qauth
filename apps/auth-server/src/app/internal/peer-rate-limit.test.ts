import { describe, expect, it } from 'vitest';

import {
  createLogSampler,
  createPeerConcurrencyLimit,
  createPeerRateLimit,
} from './peer-rate-limit';

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

  it('charges a call its cost, never more than the burst', () => {
    let now = 0;
    const limit = createPeerRateLimit({ ratePerSecond: 10, burst: 10, now: () => now });
    expect(limit.take('peer-a', 4)).toEqual({ allowed: true });
    expect(limit.take('peer-a', 4)).toEqual({ allowed: true });
    // Two tokens left: a call of four waits for two more, a fifth of a second.
    expect(limit.take('peer-a', 4)).toMatchObject({ allowed: false, retryAfterMs: 200 });
    expect(limit.take('peer-a', 2)).toEqual({ allowed: true });
    // A cost past the burst is charged as the burst: a full bucket lets it through.
    now += 1_000;
    expect(limit.take('peer-a', 1_000)).toEqual({ allowed: true });
    expect(limit.take('peer-a')).toMatchObject({ allowed: false });
  });
});

describe('createPeerConcurrencyLimit (#497)', () => {
  it('holds each peer to its cap of calls in flight', () => {
    const limit = createPeerConcurrencyLimit(2);
    expect(limit.enter('peer-a')).toBe(true);
    expect(limit.enter('peer-a')).toBe(true);
    expect(limit.enter('peer-a')).toBe(false);
    expect(limit.enter('peer-b')).toBe(true);
    limit.leave('peer-a');
    expect(limit.enter('peer-a')).toBe(true);
    expect(() => createPeerConcurrencyLimit(0)).toThrow(TypeError);
  });
});

describe('createLogSampler (#497)', () => {
  it('lets one line a minute per key through, with how many it stands for', () => {
    let now = 0;
    const sampler = createLogSampler({ maxKeys: 2, now: () => now });
    expect(sampler.take('a')).toBe(0);
    expect(sampler.take('b')).toBe(0);
    expect(sampler.take('a')).toBeUndefined();
    // Past its cap the key seen longest ago, b, is forgotten: it logs again at once.
    expect(sampler.take('c')).toBe(0);
    expect(sampler.take('b')).toBe(0);
    expect(sampler.take('c')).toBeUndefined();
    now += 60_000;
    expect(sampler.take('c')).toBe(1);
  });
});
