import { describe, expect, it, vi } from 'vitest';

import { createReadinessRegistry, DEFAULT_READINESS_CHECK_TIMEOUT_MS } from './readiness';

/**
 * THE READINESS REGISTRY (#500): the checks `GET /ready` runs, their bounded
 * results, and what the log hears of them.
 */

/** A log whose calls the assertions read. */
function recordingLog() {
  return { warn: vi.fn(), info: vi.fn() };
}

describe('createReadinessRegistry', () => {
  it('is ready with no check, and lists the checks in registration order', async () => {
    const registry = createReadinessRegistry();
    await expect(registry.run()).resolves.toEqual({ ready: true, checks: {} });

    registry.register({ name: 'database', run: async () => undefined });
    registry.register({ name: 'redis', run: async () => 'PONG' });
    expect(registry.names()).toEqual(['database', 'redis']);
    await expect(registry.run()).resolves.toEqual({
      ready: true,
      checks: { database: { status: 'ok' }, redis: { status: 'ok' } },
    });
  });

  it('refuses a name outside its grammar, and a name registered twice', () => {
    const registry = createReadinessRegistry();
    for (const name of ['', 'Database', '1db', 'db-check', 'a'.repeat(33), 'db check']) {
      expect(() => registry.register({ name, run: async () => undefined }), name).toThrow(
        "A readiness check's name"
      );
    }
    registry.register({ name: 'database', run: async () => undefined });
    expect(() => registry.register({ name: 'database', run: async () => undefined })).toThrow(
      'The readiness check database is already registered'
    );
  });

  it('fails a check that rejects or throws, naming the reason and never the error', async () => {
    const registry = createReadinessRegistry({ log: recordingLog() });
    registry.register({ name: 'database', run: async () => undefined });
    registry.register({
      name: 'redis',
      run: async () => {
        throw new Error('connect ECONNREFUSED 10.0.0.7:6379 password=hunter2');
      },
    });
    registry.register({
      name: 'kek',
      run: () => {
        throw new Error('thrown before a promise');
      },
    });

    const report = await registry.run();

    expect(report).toEqual({
      ready: false,
      checks: {
        database: { status: 'ok' },
        redis: { status: 'fail', reason: 'error' },
        kek: { status: 'fail', reason: 'error' },
      },
    });
    expect(JSON.stringify(report)).not.toContain('ECONNREFUSED');
  });

  it('fails a check that does not settle within its timeout, and answers in that time', async () => {
    const registry = createReadinessRegistry();
    registry.register({ name: 'database', run: () => new Promise(() => undefined), timeoutMs: 20 });
    const started = Date.now();

    await expect(registry.run()).resolves.toEqual({
      ready: false,
      checks: { database: { status: 'fail', reason: 'timeout' } },
    });
    expect(Date.now() - started).toBeLessThan(DEFAULT_READINESS_CHECK_TIMEOUT_MS);
  });

  it('runs a check once for the requests that ask while it runs', async () => {
    const registry = createReadinessRegistry();
    let release: (() => void) | undefined;
    const run = vi.fn(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        })
    );
    registry.register({ name: 'database', run });

    const first = registry.run();
    const second = registry.run();
    await vi.waitFor(() => expect(release).toBeDefined());
    release?.();

    await expect(Promise.all([first, second])).resolves.toEqual([
      { ready: true, checks: { database: { status: 'ok' } } },
      { ready: true, checks: { database: { status: 'ok' } } },
    ]);
    expect(run).toHaveBeenCalledTimes(1);

    await registry.run();
    expect(run).toHaveBeenCalledTimes(2);
  });

  it('reuses a success for reuseSuccessMs, and never a failure', async () => {
    let clock = 1_000;
    const registry = createReadinessRegistry({ now: () => clock });
    let healthy = true;
    const run = vi.fn(async () => {
      if (!healthy) throw new Error('down');
    });
    registry.register({ name: 'kek', run, reuseSuccessMs: 30_000 });

    await registry.run();
    clock += 29_999;
    await expect(registry.run()).resolves.toMatchObject({ ready: true });
    expect(run).toHaveBeenCalledTimes(1);

    clock += 1;
    healthy = false;
    await expect(registry.run()).resolves.toMatchObject({ ready: false });
    await expect(registry.run()).resolves.toMatchObject({ ready: false });
    expect(run).toHaveBeenCalledTimes(3);

    healthy = true;
    await expect(registry.run()).resolves.toMatchObject({ ready: true });
    expect(run).toHaveBeenCalledTimes(4);
  });

  it('logs a check once when it starts failing, with its error, and once when it recovers', async () => {
    const log = recordingLog();
    const registry = createReadinessRegistry({ log });
    let healthy = false;
    registry.register({
      name: 'outbox',
      run: async () => {
        if (!healthy) throw new TypeError('relation "event_deliveries" does not exist');
      },
    });

    await registry.run();
    await registry.run();
    expect(log.warn).toHaveBeenCalledTimes(1);
    expect(log.warn).toHaveBeenCalledWith(
      {
        check: 'outbox',
        reason: 'error',
        err: { name: 'TypeError', message: 'relation "event_deliveries" does not exist' },
      },
      expect.stringContaining('GET /ready answers 503')
    );
    expect(log.info).not.toHaveBeenCalled();

    healthy = true;
    await registry.run();
    await registry.run();
    expect(log.info).toHaveBeenCalledTimes(1);
    expect(log.info).toHaveBeenCalledWith({ check: 'outbox' }, 'A readiness check passes again');
  });
});
