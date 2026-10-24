import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { createManualClock, type ManualClock } from '../../testing/manual-clock';
import {
  DEFAULT_JOB_TIMEOUT_MS,
  defineJob,
  jitterWindowMs,
  type JobContext,
  type JobLease,
  type JobLock,
  JobRunner,
  type JobRunnerOptions,
  type JobSpec,
  JobStoppedError,
  MAX_JOB_INTERVAL_MS,
} from './job-runner';

interface LogLine {
  readonly level: string;
  readonly bindings: Record<string, unknown>;
  readonly fields: Record<string, unknown>;
  readonly msg: string;
}

/** A logger that keeps every line, with the bindings of the child it came from. */
function recordingLogger(): { log: FastifyBaseLogger; lines: LogLine[] } {
  const lines: LogLine[] = [];
  function make(bindings: Record<string, unknown>): FastifyBaseLogger {
    const write =
      (level: string) =>
      (first?: unknown, second?: unknown): void => {
        const [fields, msg] =
          typeof first === 'string'
            ? [{}, first]
            : [(first ?? {}) as Record<string, unknown>, String(second ?? '')];
        lines.push({ level, bindings, fields, msg });
      };
    return {
      level: 'trace',
      fatal: write('fatal'),
      error: write('error'),
      warn: write('warn'),
      info: write('info'),
      debug: write('debug'),
      trace: write('trace'),
      silent: () => undefined,
      child: (more: Record<string, unknown>) => make({ ...bindings, ...more }),
    } as unknown as FastifyBaseLogger;
  }
  return { log: make({}), lines };
}

/** One lock table shared by every runner of a test, as Postgres is in production. */
function memoryLock() {
  const holders = new Map<string, AbortController>();
  const releases: string[] = [];
  const lock: JobLock = {
    async tryAcquire(jobName: string): Promise<JobLease | null> {
      if (holders.has(jobName)) return null;
      const lost = new AbortController();
      holders.set(jobName, lost);
      let released = false;
      return {
        lost: lost.signal,
        async release() {
          if (released) return;
          released = true;
          if (holders.get(jobName) === lost) holders.delete(jobName);
          releases.push(jobName);
        },
      };
    },
  };
  return {
    lock,
    holders,
    releases,
    /** What a dropped connection does: the lock is gone and its holder is told. */
    drop(jobName: string): void {
      holders.get(jobName)?.abort();
      holders.delete(jobName);
    },
  };
}

/** A promise the test settles by hand. */
function deferred<T = void>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** 'pending' until `promise` has settled, once the queue has drained. */
async function stateOf(promise: Promise<unknown>): Promise<'pending' | 'settled'> {
  let state: 'pending' | 'settled' = 'pending';
  void promise.then(
    () => (state = 'settled'),
    () => (state = 'settled')
  );
  await new Promise((resolve) => setImmediate(resolve));
  return state;
}

const INTERVAL = 60_000;
const WINDOW = jitterWindowMs(INTERVAL);

function job(overrides: Partial<JobSpec> = {}) {
  return defineJob({
    name: 'test-job',
    role: 'api',
    intervalMs: INTERVAL,
    run: async () => undefined,
    ...overrides,
  });
}

function runner(
  clock: ManualClock,
  lock: JobLock,
  overrides: Partial<JobRunnerOptions> & Pick<JobRunnerOptions, 'jobs'>
) {
  const { log, lines } = recordingLogger();
  const runs = { inc: vi.fn() };
  const instance = new JobRunner({
    roles: ['api'],
    lock,
    log,
    runs,
    clock,
    random: () => 0,
    ...overrides,
  });
  return { runner: instance, lines, runs };
}

function messages(lines: LogLine[], msg: string): LogLine[] {
  return lines.filter((line) => line.msg === msg);
}

describe('defineJob', () => {
  it('limits a run to its interval, or to the default limit when the interval is longer', () => {
    expect(job({ intervalMs: 60_000 }).timeoutMs).toBe(60_000);
    expect(job({ intervalMs: 60 * 60_000 }).timeoutMs).toBe(DEFAULT_JOB_TIMEOUT_MS);
    expect(job({ intervalMs: 60 * 60_000, timeoutMs: 1_000 }).timeoutMs).toBe(1_000);
  });

  it('returns a frozen definition', () => {
    expect(Object.isFrozen(job())).toBe(true);
  });

  it.each(['', 'Purge', 'purge_expired', '-purge', 'purge-', 'purge--expired', 'a'.repeat(65)])(
    'refuses the name %j',
    (name) => {
      expect(() => job({ name })).toThrow(/kebab-case/);
    }
  );

  it('refuses an unknown role', () => {
    expect(() => job({ role: 'worker' as never })).toThrow(/unknown role/);
  });

  it.each([0, 999, 1_500.5, MAX_JOB_INTERVAL_MS + 1])('refuses the interval %d', (intervalMs) => {
    expect(() => job({ intervalMs })).toThrow(/interval/);
  });

  it.each([0, -1, 1.5, INTERVAL + 1])('refuses the time limit %d', (timeoutMs) => {
    expect(() => job({ timeoutMs })).toThrow(/time limit/);
  });
});

describe('JobRunner', () => {
  it('refuses two jobs with one name', () => {
    expect(
      () =>
        new JobRunner({
          jobs: [job(), job()],
          roles: ['api'],
          lock: memoryLock().lock,
          log: recordingLogger().log,
        })
    ).toThrow(/defined twice/);
  });

  it('starts only the jobs of the roles this node holds', async () => {
    const clock = createManualClock();
    const apiRun = vi.fn(async () => undefined);
    const signerRun = vi.fn(async () => undefined);
    const { runner: instance } = runner(clock, memoryLock().lock, {
      jobs: [
        job({ name: 'api-job', run: apiRun }),
        job({ name: 'signer-job', role: 'signer', run: signerRun }),
      ],
    });

    expect(instance.activeJobNames).toEqual(['api-job']);
    instance.start();
    await clock.advanceTo(3 * INTERVAL);

    expect(apiRun).toHaveBeenCalledTimes(3);
    expect(signerRun).not.toHaveBeenCalled();
    await instance.stop();
  });

  it('wakes once per slot, at its offset in the wake window', async () => {
    const clock = createManualClock(10_000);
    const run = vi.fn(async () => undefined);
    const { runner: instance } = runner(clock, memoryLock().lock, {
      jobs: [job({ run })],
      random: () => 0.5,
    });

    instance.start();
    expect(clock.pending()).toEqual([INTERVAL + WINDOW / 2]);

    await clock.advanceTo(INTERVAL + WINDOW / 2 - 1);
    expect(run).not.toHaveBeenCalled();
    await clock.advanceTo(INTERVAL + WINDOW / 2);
    expect(run).toHaveBeenCalledOnce();
    await clock.advanceTo(2 * INTERVAL + WINDOW / 2 - 1);
    expect(run).toHaveBeenCalledOnce();
    await clock.advanceTo(2 * INTERVAL + WINDOW / 2);
    expect(run).toHaveBeenCalledTimes(2);
    await instance.stop();
  });

  it('hands the run its clock and a logger bound to the job', async () => {
    const clock = createManualClock();
    let seen: JobContext | undefined;
    const { runner: instance, lines } = runner(clock, memoryLock().lock, {
      jobs: [
        job({
          run: async (context) => {
            seen = context;
            context.log.info('inside');
          },
        }),
      ],
    });

    instance.start();
    await clock.advanceTo(INTERVAL);

    expect(seen?.now()).toBe(INTERVAL);
    expect(seen?.signal.aborted).toBe(false);
    expect(messages(lines, 'inside')[0]?.bindings).toEqual({ job: 'test-job' });
    await instance.stop();
  });

  it('logs the start, the end and the duration of a run, and counts it', async () => {
    const clock = createManualClock();
    const gate = deferred();
    const {
      runner: instance,
      lines,
      runs,
    } = runner(clock, memoryLock().lock, {
      jobs: [job({ run: () => gate.promise })],
    });

    instance.start();
    await clock.advanceTo(INTERVAL);
    expect(messages(lines, 'job run started')).toHaveLength(1);
    expect(messages(lines, 'job run finished')).toHaveLength(0);

    await clock.advanceBy(1_500);
    gate.resolve();
    await clock.advanceBy(0);

    const [finished] = messages(lines, 'job run finished');
    expect(finished?.level).toBe('info');
    expect(finished?.bindings).toEqual({ job: 'test-job' });
    expect(finished?.fields).toEqual({ durationMs: 1_500 });
    expect(runs.inc).toHaveBeenCalledWith({ job: 'test-job', result: 'success' });
    await instance.stop();
  });

  it('runs a job once per interval across two runners sharing one lock', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    const run = vi.fn(async () => undefined);
    // Node A wakes first in odd slots, node B in even ones.
    let slotA = 0;
    let slotB = 0;
    const a = runner(clock, shared.lock, {
      jobs: [job({ run })],
      random: () => (slotA++ % 2 === 0 ? 0.1 : 0.7),
    });
    const b = runner(clock, shared.lock, {
      jobs: [job({ run })],
      random: () => (slotB++ % 2 === 0 ? 0.7 : 0.1),
    });

    a.runner.start();
    b.runner.start();
    await clock.advanceTo(4 * INTERVAL + WINDOW);

    expect(run).toHaveBeenCalledTimes(4);
    expect(messages(a.lines, 'job run finished')).toHaveLength(2);
    expect(messages(b.lines, 'job run finished')).toHaveLength(2);
    expect(messages(a.lines, 'job run skipped: another node holds its lock')).toHaveLength(2);
    expect(messages(b.lines, 'job run skipped: another node holds its lock')).toHaveLength(2);
    await a.runner.stop();
    await b.runner.stop();
  });

  it('keeps the lock after a short run until twice the wake window has passed', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    const { runner: instance } = runner(clock, shared.lock, { jobs: [job()] });

    instance.start();
    await clock.advanceTo(INTERVAL);
    expect(shared.holders.has('test-job')).toBe(true);
    await clock.advanceTo(INTERVAL + 2 * WINDOW - 1);
    expect(shared.holders.has('test-job')).toBe(true);
    await clock.advanceTo(INTERVAL + 2 * WINDOW);
    expect(shared.holders.has('test-job')).toBe(false);
    await instance.stop();
  });

  it('skips the run while another holder has the lock', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    const run = vi.fn(async () => undefined);
    const {
      runner: instance,
      lines,
      runs,
    } = runner(clock, shared.lock, {
      jobs: [job({ run })],
    });
    const elsewhere = await shared.lock.tryAcquire('test-job');

    instance.start();
    await clock.advanceTo(INTERVAL);

    expect(run).not.toHaveBeenCalled();
    expect(runs.inc).not.toHaveBeenCalled();
    expect(messages(lines, 'job run skipped: another node holds its lock')[0]?.level).toBe('debug');

    await elsewhere?.release();
    await clock.advanceTo(2 * INTERVAL);
    expect(run).toHaveBeenCalledOnce();
    await instance.stop();
  });

  it('leaves the slot to the next interval when the lock is only taken after it closed', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    const slow = deferred();
    const lock: JobLock = {
      tryAcquire: vi
        .fn()
        .mockImplementationOnce(async (name: string) => {
          await slow.promise;
          return shared.lock.tryAcquire(name);
        })
        .mockImplementation((name: string) => shared.lock.tryAcquire(name)),
    };
    const run = vi.fn(async () => undefined);
    const { runner: instance, lines, runs } = runner(clock, lock, { jobs: [job({ run })] });

    instance.start();
    await clock.advanceTo(INTERVAL);
    // Another node may already have run this slot and let go by now.
    await clock.advanceTo(INTERVAL + 2 * WINDOW);
    slow.resolve();
    await clock.advanceBy(0);

    expect(run).not.toHaveBeenCalled();
    expect(runs.inc).not.toHaveBeenCalled();
    expect(shared.holders.has('test-job')).toBe(false);
    expect(
      messages(lines, 'job run skipped: the lock was taken after its slot had closed')[0]?.level
    ).toBe('warn');

    await clock.advanceTo(2 * INTERVAL);
    expect(run).toHaveBeenCalledOnce();
    await instance.stop();
  });

  it('logs and counts a failing job, and runs it again at the next interval', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    const failure = new Error('database unavailable');
    const run = vi.fn().mockRejectedValueOnce(failure).mockResolvedValueOnce(undefined);
    const {
      runner: instance,
      lines,
      runs,
    } = runner(clock, shared.lock, {
      jobs: [job({ run })],
    });

    instance.start();
    await clock.advanceTo(INTERVAL);

    const [failed] = messages(lines, 'job run failed');
    expect(failed?.level).toBe('error');
    expect(failed?.fields).toEqual({ err: failure, durationMs: 0 });
    expect(runs.inc).toHaveBeenCalledWith({ job: 'test-job', result: 'failure' });

    await clock.advanceTo(2 * INTERVAL);
    expect(run).toHaveBeenCalledTimes(2);
    expect(runs.inc).toHaveBeenLastCalledWith({ job: 'test-job', result: 'success' });
    await instance.stop();
  });

  it('stops a job at its time limit and releases its lock', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    // Wake window 1 s and a 5 s limit: the lock is not held past the limit.
    const interval = 10_000;
    let reason: unknown;
    const run = vi.fn(
      ({ signal }: JobContext) =>
        new Promise<void>((_, reject) => {
          signal.addEventListener('abort', () => {
            reason = signal.reason;
            reject(signal.reason as Error);
          });
        })
    );
    const {
      runner: instance,
      lines,
      runs,
    } = runner(clock, shared.lock, {
      jobs: [job({ intervalMs: interval, timeoutMs: 5_000, run })],
    });

    instance.start();
    await clock.advanceTo(interval + 4_999);
    expect(shared.holders.has('test-job')).toBe(true);
    await clock.advanceTo(interval + 5_000);

    expect(reason).toBeInstanceOf(JobStoppedError);
    expect((reason as JobStoppedError).stopReason).toBe('timeout');
    expect(shared.holders.has('test-job')).toBe(false);
    expect(shared.releases).toEqual(['test-job']);
    expect(runs.inc).toHaveBeenCalledWith({ job: 'test-job', result: 'timeout' });
    expect(messages(lines, 'job run exceeded its time limit and was stopped')[0]?.fields).toEqual({
      durationMs: 5_000,
      timeoutMs: 5_000,
    });

    await clock.advanceTo(2 * interval);
    expect(run).toHaveBeenCalledTimes(2);
    await instance.stop();
  });

  it('does not start a job again on this node until a run that ignored its limit settles', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    const interval = 10_000;
    const stuck = deferred();
    const run = vi.fn().mockReturnValueOnce(stuck.promise).mockResolvedValue(undefined);
    const { runner: instance, lines } = runner(clock, shared.lock, {
      jobs: [job({ intervalMs: interval, timeoutMs: 5_000, run })],
    });

    instance.start();
    await clock.advanceTo(interval + 5_000);
    // The lock is free for another node, but this node waits for its own run.
    expect(shared.holders.has('test-job')).toBe(false);

    await clock.advanceTo(2 * interval);
    expect(run).toHaveBeenCalledOnce();
    expect(
      messages(lines, 'job run skipped: its previous run on this node has not ended')[0]?.level
    ).toBe('warn');

    stuck.resolve();
    await clock.advanceTo(3 * interval);
    expect(run).toHaveBeenCalledTimes(2);
    await instance.stop();
  });

  it('stops a run whose lock is lost and counts it as a failure', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    let reason: unknown;
    const run = ({ signal }: JobContext) =>
      new Promise<void>((resolve) => {
        signal.addEventListener('abort', () => {
          reason = signal.reason;
          resolve();
        });
      });
    const {
      runner: instance,
      lines,
      runs,
    } = runner(clock, shared.lock, {
      jobs: [job({ run })],
    });

    instance.start();
    await clock.advanceTo(INTERVAL);
    shared.drop('test-job');
    await clock.advanceBy(0);

    expect((reason as JobStoppedError).stopReason).toBe('lock_lost');
    expect(runs.inc).toHaveBeenCalledWith({ job: 'test-job', result: 'failure' });
    expect(messages(lines, 'job lock was lost during the run; the run was stopped')[0]?.level).toBe(
      'error'
    );
    expect(shared.releases).toEqual(['test-job']);
    await instance.stop();
  });

  it('logs and counts a lock that cannot be taken, and tries again at the next interval', async () => {
    const clock = createManualClock();
    const shared = memoryLock();
    const failure = new Error('connection refused');
    const lock: JobLock = {
      tryAcquire: vi
        .fn()
        .mockRejectedValueOnce(failure)
        .mockImplementation((name: string) => shared.lock.tryAcquire(name)),
    };
    const run = vi.fn(async () => undefined);
    const { runner: instance, lines, runs } = runner(clock, lock, { jobs: [job({ run })] });

    instance.start();
    await clock.advanceTo(INTERVAL);
    expect(run).not.toHaveBeenCalled();
    expect(
      messages(lines, 'job lock could not be taken; the run waits for the next interval')[0]?.fields
    ).toEqual({ err: failure });
    expect(runs.inc).toHaveBeenCalledWith({ job: 'test-job', result: 'failure' });

    await clock.advanceTo(2 * INTERVAL);
    expect(run).toHaveBeenCalledOnce();
    await instance.stop();
  });

  describe('stop', () => {
    it('tells a running job to stop and waits for it', async () => {
      const clock = createManualClock();
      const shared = memoryLock();
      const gate = deferred();
      let signal: AbortSignal | undefined;
      const {
        runner: instance,
        lines,
        runs,
      } = runner(clock, shared.lock, {
        jobs: [
          job({
            run: (context) => {
              signal = context.signal;
              return gate.promise;
            },
          }),
        ],
      });

      instance.start();
      await clock.advanceTo(INTERVAL);
      const stopping = instance.stop();

      expect((signal?.reason as JobStoppedError | undefined)?.stopReason).toBe('shutdown');
      expect(await stateOf(stopping)).toBe('pending');
      expect(shared.holders.has('test-job')).toBe(true);

      gate.resolve();
      await expect(stopping).resolves.toBeUndefined();
      expect(shared.holders.has('test-job')).toBe(false);
      expect(runs.inc).toHaveBeenCalledWith({ job: 'test-job', result: 'success' });
      expect(messages(lines, 'job runner stopped')).toHaveLength(1);
      expect(clock.pending()).toEqual([]);
    });

    it('gives up on a job at the shutdown limit, releases its lock and resolves', async () => {
      const clock = createManualClock();
      const shared = memoryLock();
      const { runner: instance, lines } = runner(clock, shared.lock, {
        jobs: [job({ run: () => new Promise<void>(() => undefined) })],
        shutdownTimeoutMs: 2_000,
      });

      instance.start();
      await clock.advanceTo(INTERVAL);
      const stopping = instance.stop();

      await clock.advanceBy(1_999);
      expect(await stateOf(stopping)).toBe('pending');
      await clock.advanceBy(1);

      await expect(stopping).resolves.toBeUndefined();
      expect(shared.holders.has('test-job')).toBe(false);
      expect(
        messages(lines, 'jobs still running at the shutdown limit; releasing their locks')[0]
          ?.fields
      ).toEqual({ jobs: ['test-job'], shutdownTimeoutMs: 2_000 });
      expect(
        messages(lines, 'job run outlasted the shutdown limit and was given up on')
      ).toHaveLength(1);
    });

    it('ends the hold of a finished run at once', async () => {
      const clock = createManualClock();
      const shared = memoryLock();
      const { runner: instance } = runner(clock, shared.lock, { jobs: [job()] });

      instance.start();
      await clock.advanceTo(INTERVAL);
      expect(shared.holders.has('test-job')).toBe(true);

      await instance.stop();
      expect(shared.holders.has('test-job')).toBe(false);
    });

    it('runs nothing after it is called', async () => {
      const clock = createManualClock();
      const run = vi.fn(async () => undefined);
      const { runner: instance } = runner(clock, memoryLock().lock, { jobs: [job({ run })] });

      instance.start();
      await instance.stop();
      await clock.advanceTo(3 * INTERVAL);

      expect(run).not.toHaveBeenCalled();
      expect(() => instance.start()).toThrow(/started once/);
    });

    it('can be called before start and more than once', async () => {
      const clock = createManualClock();
      const { runner: instance, lines } = runner(clock, memoryLock().lock, { jobs: [job()] });

      const first = instance.stop();
      expect(instance.stop()).toBe(first);
      await first;
      expect(messages(lines, 'job runner stopped')).toHaveLength(0);
    });
  });
});
