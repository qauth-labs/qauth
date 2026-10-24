import { describe, expect, it } from 'vitest';

import { checkRetrySchedule, DEFAULT_RETRY_SCHEDULE, retryDelayMs } from './retry';

describe('retryDelayMs', () => {
  const schedule = { initialDelayMs: 1_000, maxDelayMs: 10_000, multiplier: 2, jitter: 0.2 };

  it('doubles from the first delay up to the cap, before jitter', () => {
    const noJitter = () => 0;
    expect([1, 2, 3, 4, 5, 6].map((attempt) => retryDelayMs(attempt, schedule, noJitter))).toEqual([
      1_000, 2_000, 4_000, 8_000, 10_000, 10_000,
    ]);
  });

  it('takes off at most the jitter share, at random', () => {
    expect(retryDelayMs(1, schedule, () => 0.5)).toBe(900);
    expect(retryDelayMs(1, schedule, () => 0.999999)).toBe(800);
  });

  it('grows with every attempt until the cap, whatever the jitter draws', () => {
    // The worst case: the longest draw, then the shortest.
    for (let attempt = 1; attempt < 4; attempt += 1) {
      expect(retryDelayMs(attempt + 1, schedule, () => 0.999999)).toBeGreaterThan(
        retryDelayMs(attempt, schedule, () => 0)
      );
    }
  });

  it('refuses an attempt number that is not a whole number from 1', () => {
    expect(() => retryDelayMs(0, schedule)).toThrow(TypeError);
    expect(() => retryDelayMs(1.5, schedule)).toThrow(TypeError);
  });

  it('spreads the default schedule over 11.6 to 14.5 hours for 12 attempts', () => {
    const total = (draw: number) =>
      Array.from({ length: 11 }, (_, i) =>
        retryDelayMs(i + 1, DEFAULT_RETRY_SCHEDULE, () => draw)
      ).reduce((sum, delay) => sum + delay, 0);
    expect(total(0) / 3_600_000).toBeCloseTo(14.525, 2);
    expect(total(0.999999) / 3_600_000).toBeCloseTo(11.62, 2);
  });
});

describe('checkRetrySchedule', () => {
  const valid = { initialDelayMs: 1_000, maxDelayMs: 10_000, multiplier: 2, jitter: 0.2 };

  it('accepts a schedule and freezes it', () => {
    expect(Object.isFrozen(checkRetrySchedule(valid))).toBe(true);
  });

  it.each([
    ['a first delay of 0', { initialDelayMs: 0 }],
    ['a fractional delay', { initialDelayMs: 1.5 }],
    ['a cap below the first delay', { maxDelayMs: 500 }],
    ['a cap over 7 days', { maxDelayMs: 8 * 24 * 3_600_000 }],
    ['a multiplier below 1', { multiplier: 0.5 }],
    ['a jitter of 1', { jitter: 1 }],
    ['a negative jitter', { jitter: -0.1 }],
  ])('refuses %s', (_label, change) => {
    expect(() => checkRetrySchedule({ ...valid, ...change })).toThrow(TypeError);
  });
});
