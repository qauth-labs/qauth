import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

/**
 * The bounded Argon2 queue (#751, GHSA-7fxx-3c59-jx98).
 *
 * `@node-rs/argon2` is replaced by jobs the test finishes by hand, so a slot
 * stays busy for exactly as long as the test wants and every hash the hasher
 * starts is counted. The module is loaded fresh per test, with a 4-thread pool,
 * so its slot count (2) and its queue start empty.
 */

/** One Argon2 job the hasher started and the test has not finished yet. */
interface PendingJob {
  finish(valid: boolean): void;
}

const started: PendingJob[] = [];

vi.mock('@node-rs/argon2', () => ({
  hash: vi.fn(async () => '$argon2id$stub'),
  verify: vi.fn(
    () =>
      new Promise<boolean>((resolve) => {
        started.push({ finish: resolve });
      })
  ),
}));

type PasswordHashModule = typeof import('./password-hash');

/** Let every settled promise run its continuations. */
async function flush(): Promise<void> {
  for (let i = 0; i < 10; i++) await Promise.resolve();
}

describe('Argon2 queue limit', () => {
  let module: PasswordHashModule;

  beforeEach(async () => {
    started.length = 0;
    vi.stubEnv('UV_THREADPOOL_SIZE', '4');
    vi.resetModules();
    module = await import('./password-hash');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  /**
   * Fill both slots and put `waiting` verifications in the queue, none of
   * them shed. Returns their results, in order.
   */
  async function occupy(
    hasher: ReturnType<PasswordHashModule['createPasswordHasher']>,
    waiting: number
  ): Promise<Promise<boolean>[]> {
    const results = Array.from({ length: 2 + waiting }, () =>
      hasher.verifyPassword('$argon2id$stored', 'presented')
    );
    await flush();
    // Two slots: only two hashes started, the rest wait in the queue.
    expect(started).toHaveLength(2);
    return results;
  }

  /** Finish the job in the oldest slot and let the queue hand it over. */
  async function finishOldest(valid = false): Promise<void> {
    started.shift()?.finish(valid);
    await flush();
  }

  it('refuses a verification at once, with no hash computed, when the queue is full', async () => {
    const hasher = module.createPasswordHasher({ queueLimit: 3 });
    const queued = await occupy(hasher, 3);

    const shed = hasher.verifyPassword('$argon2id$stored', 'presented', {
      shedWhenQueueFull: true,
    });

    // Refused while both slots are still busy: nothing it could have waited
    // for has finished.
    await expect(shed).rejects.toBeInstanceOf(module.Argon2QueueFullError);
    await expect(shed).rejects.toMatchObject({ queued: 3, queueLimit: 3 });
    const { verify } = await import('@node-rs/argon2');
    expect(verify).toHaveBeenCalledTimes(2);
    expect(started).toHaveLength(2);

    // The refusal took neither a slot nor a place in the queue: the five
    // verifications in front of it all run, each in its turn.
    for (let i = 0; i < 5; i++) await finishOldest(true);
    expect(await Promise.all(queued)).toEqual(Array(5).fill(true));
    expect(verify).toHaveBeenCalledTimes(5);
    expect(started).toHaveLength(0);
  });

  it('admits a verification that asks to be shed while the queue is below the limit', async () => {
    const hasher = module.createPasswordHasher({ queueLimit: 3 });
    const queued = await occupy(hasher, 2);

    const admitted = hasher.verifyPassword('$argon2id$stored', 'presented', {
      shedWhenQueueFull: true,
    });
    for (let i = 0; i < 5; i++) await finishOldest(true);

    expect(await admitted).toBe(true);
    expect(await Promise.all(queued)).toEqual(Array(4).fill(true));
  });

  it('admits a shed verification again once the queue drains below the limit', async () => {
    const hasher = module.createPasswordHasher({ queueLimit: 1 });
    const queued = await occupy(hasher, 1);

    await expect(
      hasher.verifyPassword('$argon2id$stored', 'presented', { shedWhenQueueFull: true })
    ).rejects.toBeInstanceOf(module.Argon2QueueFullError);

    // One slot finishes and the waiting job takes it: the queue is empty.
    await finishOldest();
    const admitted = hasher.verifyPassword('$argon2id$stored', 'presented', {
      shedWhenQueueFull: true,
    });
    await flush();
    expect(started).toHaveLength(2);

    while (started.length > 0) await finishOldest(true);
    expect(await admitted).toBe(true);
    expect(await Promise.all(queued)).toEqual([false, true, true]);
  });

  it('queues a verification that does not ask to be shed, however long the queue is', async () => {
    // Logins, registrations and the login decoy keep waiting: shedding is
    // asked for per call, by the client-secret check.
    const hasher = module.createPasswordHasher({ queueLimit: 0 });
    const queued = await occupy(hasher, 5);

    while (started.length > 0) await finishOldest(true);
    expect(await Promise.all(queued)).toEqual(Array(7).fill(true));
  });

  it('with a limit of 0, refuses a shed verification whenever every slot is busy', async () => {
    const hasher = module.createPasswordHasher({ queueLimit: 0 });
    const running = await occupy(hasher, 0);

    await expect(
      hasher.verifyPassword('$argon2id$stored', 'presented', { shedWhenQueueFull: true })
    ).rejects.toMatchObject({ queued: 0, queueLimit: 0 });

    await finishOldest(true);
    // A free slot: admitted, and started at once.
    const admitted = hasher.verifyPassword('$argon2id$stored', 'presented', {
      shedWhenQueueFull: true,
    });
    await flush();
    expect(started).toHaveLength(2);
    while (started.length > 0) await finishOldest(false);
    expect(await admitted).toBe(false);
    expect(await Promise.all(running)).toEqual([true, false]);
  });

  it('counts the jobs of every hasher in the process against the limit', async () => {
    // The slots and the queue belong to the libuv pool, not to one hasher.
    const logins = module.createPasswordHasher({ queueLimit: 32 });
    const clientSecrets = module.createPasswordHasher({ queueLimit: 2 });
    const queued = await occupy(logins, 2);

    await expect(
      clientSecrets.verifyPassword('$argon2id$stored', 'presented', { shedWhenQueueFull: true })
    ).rejects.toBeInstanceOf(module.Argon2QueueFullError);

    while (started.length > 0) await finishOldest(true);
    expect(await Promise.all(queued)).toEqual(Array(4).fill(true));
  });

  it('still answers false, not a refusal, for a shed verification Argon2 rejects', async () => {
    const hasher = module.createPasswordHasher();
    const { verify } = await import('@node-rs/argon2');
    vi.mocked(verify).mockRejectedValueOnce(new Error('invalid hash'));

    await expect(
      hasher.verifyPassword('not-a-hash', 'presented', { shedWhenQueueFull: true })
    ).resolves.toBe(false);
  });
});

describe('queueLimit configuration', () => {
  it('defaults to 32', async () => {
    const { DEFAULT_PASSWORD_CONFIG } = await import('./password-hash');
    expect(DEFAULT_PASSWORD_CONFIG.queueLimit).toBe(32);
  });

  it('refuses a negative or fractional limit', async () => {
    const { createPasswordHasher } = await import('./password-hash');
    expect(() => createPasswordHasher({ queueLimit: -1 })).toThrow();
    expect(() => createPasswordHasher({ queueLimit: 1.5 })).toThrow();
  });
});
