import { describe, expect, it } from 'vitest';

import { createProcessRateLimit } from './process-rate-limit';

/** THE IN-PROCESS RATE LIMIT of `/health` and `/ready` (#500). */

describe('createProcessRateLimit', () => {
  it('admits max requests per key and window, then refuses until the window ends', () => {
    let clock = 0;
    const limit = createProcessRateLimit({ max: 2, windowMs: 10_000, now: () => clock });

    expect(limit('a')).toEqual({ allowed: true, limit: 2, remaining: 1, resetSeconds: 10 });
    clock = 2_500;
    expect(limit('a')).toEqual({ allowed: true, limit: 2, remaining: 0, resetSeconds: 8 });
    expect(limit('a')).toEqual({ allowed: false, limit: 2, remaining: 0, resetSeconds: 8 });
    // Another key counts on its own.
    expect(limit('b')).toMatchObject({ allowed: true, remaining: 1 });

    clock = 9_999;
    expect(limit('a')).toMatchObject({ allowed: false, resetSeconds: 1 });
    clock = 10_000;
    expect(limit('a')).toEqual({ allowed: true, limit: 2, remaining: 1, resetSeconds: 10 });
  });

  it('counts at most maxKeys keys, dropping the expired ones first, then the oldest', () => {
    let clock = 0;
    const limit = createProcessRateLimit({ max: 1, windowMs: 1_000, maxKeys: 2, now: () => clock });

    limit('old');
    clock = 500;
    limit('newer');
    // A third key pushes out the oldest, which starts counting again.
    limit('third');
    expect(limit('old')).toMatchObject({ allowed: true });
    // `newer` was pushed out by `old`: it counts again too.
    expect(limit('newer')).toMatchObject({ allowed: true });

    clock = 5_000;
    // Every bucket has expired: a new key takes the room of the expired ones.
    limit('fresh');
    expect(limit('fresh')).toMatchObject({ allowed: false });
  });
});
