import { EventEmitter } from 'node:events';

import type { FastifyBaseLogger } from 'fastify';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ADVISORY_UNLOCK_TIMEOUT_MS,
  type AdvisoryLockClient,
  advisoryLockKey,
  createAdvisoryJobLock,
} from './advisory-lock';

/** A pool client that answers each statement from `answers`, in order. */
class FakeClient extends EventEmitter {
  readonly statements: Array<{ text: string; values: unknown[] }> = [];
  readonly release = vi.fn<(destroy?: Error | boolean) => void>();

  constructor(
    private readonly answers: Array<() => Promise<{ rows: Array<Record<string, unknown>> }>>
  ) {
    super();
  }

  query(text: string, values: unknown[]) {
    this.statements.push({ text, values });
    const answer = this.answers.shift();
    if (!answer) throw new Error(`unexpected statement: ${text}`);
    return answer();
  }
}

const row = (value: Record<string, unknown>) => async () => ({ rows: [value] });

function setup(answers: Array<() => Promise<{ rows: Array<Record<string, unknown>> }>>) {
  const client = new FakeClient(answers);
  const pool = { connect: vi.fn(async () => client as unknown as AdvisoryLockClient) };
  const log = { warn: vi.fn() } as unknown as FastifyBaseLogger & {
    warn: ReturnType<typeof vi.fn>;
  };
  return { client, pool, log, lock: createAdvisoryJobLock(pool, log) };
}

afterEach(() => {
  vi.useRealTimers();
});

describe('advisoryLockKey', () => {
  it('is the same for one name on every node and differs between names', () => {
    expect(advisoryLockKey('purge-expired')).toBe(advisoryLockKey('purge-expired'));
    expect(advisoryLockKey('purge-expired')).not.toBe(advisoryLockKey('rotate-keys'));
  });

  it('fits a Postgres bigint', () => {
    for (const name of ['purge-expired', 'rotate-keys', 'a', 'session-purge']) {
      const key = BigInt(advisoryLockKey(name));
      expect(key >= -(2n ** 63n) && key < 2n ** 63n).toBe(true);
    }
  });
});

describe('createAdvisoryJobLock', () => {
  it('takes a session-level lock on a connection of its own', async () => {
    const { client, pool, lock } = setup([row({ acquired: true })]);

    const lease = await lock.tryAcquire('purge-expired');

    expect(lease).not.toBeNull();
    expect(pool.connect).toHaveBeenCalledOnce();
    expect(client.statements).toEqual([
      {
        text: 'SELECT pg_try_advisory_lock($1::bigint) AS acquired',
        values: [advisoryLockKey('purge-expired')],
      },
    ]);
    // The connection stays out of the pool while the lock is held.
    expect(client.release).not.toHaveBeenCalled();
    expect(client.listenerCount('error')).toBe(1);
  });

  it('returns null and gives the connection back when another session holds the lock', async () => {
    const { client, lock } = setup([row({ acquired: false })]);

    await expect(lock.tryAcquire('purge-expired')).resolves.toBeNull();

    expect(client.release).toHaveBeenCalledWith();
    expect(client.listenerCount('error')).toBe(0);
    expect(client.listenerCount('end')).toBe(0);
  });

  it('unlocks and gives the connection back on release, once', async () => {
    const { client, lock } = setup([row({ acquired: true }), row({ released: true })]);
    const lease = await lock.tryAcquire('purge-expired');

    await Promise.all([lease?.release(), lease?.release()]);

    expect(client.statements[1]).toEqual({
      text: 'SELECT pg_advisory_unlock($1::bigint) AS released',
      values: [advisoryLockKey('purge-expired')],
    });
    expect(client.statements).toHaveLength(2);
    expect(client.release).toHaveBeenCalledOnce();
    expect(client.release).toHaveBeenCalledWith();
    expect(client.listenerCount('error')).toBe(0);
  });

  it('marks the lease lost when its connection fails, and closes the connection on release', async () => {
    const { client, lock, log } = setup([row({ acquired: true })]);
    const lease = await lock.tryAcquire('purge-expired');
    const failure = new Error('terminating connection due to administrator command');

    client.emit('error', failure);

    expect(lease?.lost.aborted).toBe(true);
    expect(lease?.lost.reason).toBe(failure);
    expect(log.warn).toHaveBeenCalledWith(
      { err: failure, job: 'purge-expired' },
      'job lock connection failed; the lock is lost'
    );

    await lease?.release();
    expect(client.statements).toHaveLength(1);
    expect(client.release).toHaveBeenCalledWith(true);
    // Errors the closing connection still emits have a listener.
    expect(() => client.emit('error', new Error('again'))).not.toThrow();
  });

  it('marks the lease lost when its connection ends', async () => {
    const { client, lock } = setup([row({ acquired: true })]);
    const lease = await lock.tryAcquire('purge-expired');

    client.emit('end');

    expect(lease?.lost.aborted).toBe(true);
  });

  it('closes the connection when the unlock fails', async () => {
    const failure = new Error('connection reset');
    const { client, lock, log } = setup([row({ acquired: true }), () => Promise.reject(failure)]);
    const lease = await lock.tryAcquire('purge-expired');

    await expect(lease?.release()).resolves.toBeUndefined();

    expect(client.release).toHaveBeenCalledWith(failure);
    expect(log.warn).toHaveBeenCalledWith(
      { err: failure, job: 'purge-expired' },
      'job lock could not be released; closing its connection'
    );
  });

  it('closes the connection when the lock was not held at release', async () => {
    const { client, lock } = setup([row({ acquired: true }), row({ released: false })]);
    const lease = await lock.tryAcquire('purge-expired');

    await lease?.release();

    expect(client.release).toHaveBeenCalledWith(true);
  });

  it('closes the connection when the unlock does not answer in time', async () => {
    vi.useFakeTimers();
    const { client, lock } = setup([row({ acquired: true }), () => new Promise(() => undefined)]);
    const lease = await lock.tryAcquire('purge-expired');

    const releasing = lease?.release();
    await vi.advanceTimersByTimeAsync(ADVISORY_UNLOCK_TIMEOUT_MS);
    await releasing;

    expect(client.release).toHaveBeenCalledWith(expect.any(Error));
  });

  it('closes the connection and rethrows when the lock query fails', async () => {
    const failure = new Error('relation does not exist');
    const { client, lock } = setup([() => Promise.reject(failure)]);

    await expect(lock.tryAcquire('purge-expired')).rejects.toBe(failure);

    expect(client.release).toHaveBeenCalledWith(failure);
  });

  it('rethrows when no connection can be had', async () => {
    const failure = new Error('timeout exceeded when trying to connect');
    const pool = { connect: vi.fn(async () => Promise.reject(failure)) };
    const lock = createAdvisoryJobLock(pool, { warn: vi.fn() } as unknown as FastifyBaseLogger);

    await expect(lock.tryAcquire('purge-expired')).rejects.toBe(failure);
  });
});
