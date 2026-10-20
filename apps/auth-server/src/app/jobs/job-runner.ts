import type { FastifyBaseLogger } from 'fastify';

/**
 * BACKGROUND JOBS (ADR-019 Decision 8).
 *
 * A job is periodic work with no caller: purging expired rows, rotating keys,
 * purging ended sessions. Every node of a deployment runs the same codebase, so
 * every node would run every job; a Postgres advisory lock per job name keeps
 * each job on one node at a time. The one exception is a run that ignores its
 * signal (below): it can still be going when the lock passes to another node.
 *
 * There is no queue, no retry store and no cron syntax. A job runs on a fixed
 * interval and must be safe to repeat: a run that fails, times out or dies with
 * its node is simply run again at the next interval.
 *
 * ## Once per interval, on one node
 *
 * Time is cut into slots of `intervalMs`, aligned to the epoch, so every node
 * agrees where a slot starts. Each node wakes once per slot at a random offset
 * inside the slot's wake window (the jitter, {@link jitterWindowMs}), so the
 * nodes do not hit the database together. The first node to wake takes the
 * lock and runs the job.
 *
 * A lock that is released the moment a short run ends would not stop the nodes
 * that wake after it in the same window: each would find the lock free and run
 * the job again. So the node that won the slot keeps the lock until its run has
 * ended AND twice the wake window has passed since the slot started. The second
 * window is the allowance for clock skew between nodes and for late timers. A
 * node that wakes while the lock is held skips the slot, and so does a node
 * that only gets the lock once that time has passed.
 *
 * The lock is a session-level lock on a connection of its own, so it lasts as
 * long as the run, however long that is, and Postgres drops it when that
 * connection drops. A node that dies mid-run therefore frees the job for the
 * next node that wakes.
 *
 * ## Stopping a run
 *
 * A run is handed an `AbortSignal`. It is aborted when the run reaches its time
 * limit, when the lock's connection drops, and at shutdown. JavaScript cannot
 * kill a promise, so a job that ignores the signal keeps running in the
 * background; the runner stops waiting for it, records the outcome and releases
 * the lock. It does not start that job again on this node until the abandoned
 * run has settled.
 */

/**
 * The service roles a job can be placed on (ADR-019 Decision 8).
 *
 * The names are the role switch's proposal (`SERVICE_ROLES`, #495), which owns
 * the set once it lands. Until then a deployment is a single process that holds
 * every role, so every job runs in it.
 */
export const SERVICE_ROLES = ['web', 'api', 'admin', 'signer', 'delivery'] as const;

/** One of {@link SERVICE_ROLES}. */
export type ServiceRole = (typeof SERVICE_ROLES)[number];

/** What a run is handed. */
export interface JobContext {
  /**
   * Aborted when the run must stop: it reached its time limit, its lock was
   * lost, or the server is shutting down. The reason is a {@link JobStoppedError}.
   * A job that does a series of steps checks it between them.
   */
  readonly signal: AbortSignal;
  /** The runner's clock, in epoch milliseconds. Tests inject it. */
  now(): number;
  /** A logger bound to the job's name. */
  readonly log: FastifyBaseLogger;
}

/** What {@link defineJob} takes. */
export interface JobSpec {
  /** Unique, kebab-case. It names the lock, the log lines and the metric label. */
  readonly name: string;
  /** The role whose nodes run the job. */
  readonly role: ServiceRole;
  /** How often the job runs, in milliseconds. */
  readonly intervalMs: number;
  /**
   * The time limit of one run, in milliseconds. At most `intervalMs`. Defaults
   * to `intervalMs` or {@link DEFAULT_JOB_TIMEOUT_MS}, whichever is shorter.
   */
  readonly timeoutMs?: number;
  /** One run. It must be safe to repeat. */
  run(context: JobContext): Promise<void>;
}

/** A validated job, as {@link defineJob} returns it. */
export interface JobDefinition extends JobSpec {
  readonly timeoutMs: number;
}

/** The time limit of a run whose job sets none and runs less often than this. */
export const DEFAULT_JOB_TIMEOUT_MS = 5 * 60_000;

/** The shortest interval a job may have. */
export const MIN_JOB_INTERVAL_MS = 1_000;

/**
 * The longest interval a job may have: 24 days. A Node.js timer cannot wait
 * longer than 2^31 - 1 ms (24.8 days), and the wait for the next slot can be an
 * interval plus the jitter window.
 */
export const MAX_JOB_INTERVAL_MS = 24 * 24 * 60 * 60_000;

/** The wake window, as a share of the interval. */
export const JOB_JITTER_RATIO = 0.1;

/** The longest wake window, whatever the interval. */
export const JOB_MAX_JITTER_MS = 5 * 60_000;

/** How long shutdown waits for running jobs before it gives up on them. */
export const JOB_SHUTDOWN_TIMEOUT_MS = 5_000;

const JOB_NAME_PATTERN = /^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$/;
const JOB_NAME_MAX_LENGTH = 64;

/**
 * The window after a slot starts in which each node wakes for it: 10% of the
 * interval, and at most five minutes.
 */
export function jitterWindowMs(intervalMs: number): number {
  return Math.min(Math.floor(intervalMs * JOB_JITTER_RATIO), JOB_MAX_JITTER_MS);
}

/**
 * Validate a job and fill in its defaults.
 *
 * @throws When the name is not kebab-case, the role is unknown, or the interval
 *   or time limit is out of range. A job is defined at boot, so a mistake fails
 *   the boot.
 */
export function defineJob(spec: JobSpec): JobDefinition {
  if (spec.name.length > JOB_NAME_MAX_LENGTH || !JOB_NAME_PATTERN.test(spec.name)) {
    throw new Error(
      `Job name "${spec.name}" must be kebab-case and at most ${JOB_NAME_MAX_LENGTH} characters`
    );
  }
  if (!(SERVICE_ROLES as readonly string[]).includes(spec.role)) {
    throw new Error(`Job "${spec.name}" names an unknown role "${spec.role}"`);
  }
  if (
    !Number.isSafeInteger(spec.intervalMs) ||
    spec.intervalMs < MIN_JOB_INTERVAL_MS ||
    spec.intervalMs > MAX_JOB_INTERVAL_MS
  ) {
    throw new Error(
      `Job "${spec.name}" needs an interval of ${MIN_JOB_INTERVAL_MS} to ${MAX_JOB_INTERVAL_MS} ms`
    );
  }
  const timeoutMs = spec.timeoutMs ?? Math.min(spec.intervalMs, DEFAULT_JOB_TIMEOUT_MS);
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > spec.intervalMs) {
    throw new Error(`Job "${spec.name}" needs a time limit above 0 and at most its interval`);
  }
  return Object.freeze({
    name: spec.name,
    role: spec.role,
    intervalMs: spec.intervalMs,
    timeoutMs,
    run: spec.run,
  });
}

/** Why a run's signal was aborted. */
export type JobStopReason = 'timeout' | 'lock_lost' | 'shutdown';

/** The abort reason a run's signal carries. */
export class JobStoppedError extends Error {
  readonly stopReason: JobStopReason;

  constructor(stopReason: JobStopReason) {
    super(`Job run stopped: ${stopReason}`);
    this.name = 'JobStoppedError';
    this.stopReason = stopReason;
  }
}

/**
 * Time and timers, injectable so a test can move time by hand
 * (`src/testing/manual-clock.ts`).
 */
export interface JobClock {
  /** Epoch milliseconds. */
  now(): number;
  /** Call `callback` once, `delayMs` from now. Returns a handle for {@link clearTimeout}. */
  setTimeout(callback: () => void, delayMs: number): unknown;
  /** Cancel a callback that has not run yet. */
  clearTimeout(timer: unknown): void;
}

/**
 * The real clock. Its timers are unref'd: a waiting job never keeps the process
 * alive on its own.
 */
export const systemClock: JobClock = Object.freeze({
  now: () => Date.now(),
  setTimeout(callback: () => void, delayMs: number): unknown {
    return setTimeout(callback, delayMs).unref();
  },
  clearTimeout(timer: unknown): void {
    clearTimeout(timer as ReturnType<typeof setTimeout>);
  },
});

/** A held job lock. */
export interface JobLease {
  /** Aborted when the lock is lost before it is released, e.g. its connection dropped. */
  readonly lost: AbortSignal;
  /** Give the lock back. Resolves once it is given back; never rejects. */
  release(): Promise<void>;
}

/** Mutual exclusion of a job across the nodes of a deployment. */
export interface JobLock {
  /**
   * Take the lock of one job without waiting.
   *
   * @returns The lease, or `null` when another holder has the lock.
   */
  tryAcquire(jobName: string): Promise<JobLease | null>;
}

/** How one run ended, as the metric labels it. */
export type JobRunResult = 'success' | 'failure' | 'timeout';

/** The run counter (`qauth_job_runs_total`); a prom-client `Counter` fits. */
export interface JobRunCounter {
  inc(labels: { job: string; result: JobRunResult }): void;
}

/** What a {@link JobRunner} is built from. */
export interface JobRunnerOptions {
  /** Every job the server defines. Names must be unique. */
  readonly jobs: readonly JobDefinition[];
  /** The roles this node holds. Only their jobs are started. */
  readonly roles: readonly ServiceRole[];
  /** The cross-node lock. */
  readonly lock: JobLock;
  readonly log: FastifyBaseLogger;
  /** Counts runs by outcome. */
  readonly runs?: JobRunCounter;
  /** Defaults to {@link systemClock}. */
  readonly clock?: JobClock;
  /** Where in the wake window a node wakes: a number in [0, 1). Defaults to `Math.random`. */
  readonly random?: () => number;
  /** Defaults to {@link JOB_SHUTDOWN_TIMEOUT_MS}. */
  readonly shutdownTimeoutMs?: number;
}

type RunOutcome =
  | { readonly kind: 'success' }
  | { readonly kind: 'failure'; readonly error: unknown }
  | { readonly kind: 'timeout' }
  | { readonly kind: 'lock_lost' }
  | { readonly kind: 'abandoned' };

/**
 * Add an abort listener and return its removal. Calls `listener` at once when
 * the signal is already aborted.
 */
function onAbort(signal: AbortSignal, listener: () => void): () => void {
  if (signal.aborted) {
    listener();
    return () => undefined;
  }
  signal.addEventListener('abort', listener, { once: true });
  return () => signal.removeEventListener('abort', listener);
}

/**
 * Starts the jobs of this node's roles, runs each at its interval under its
 * lock, and stops them at shutdown.
 */
export class JobRunner {
  /** The jobs this node runs: those whose role it holds. */
  readonly activeJobNames: readonly string[];

  private readonly active: readonly JobDefinition[];
  private readonly lock: JobLock;
  private readonly log: FastifyBaseLogger;
  private readonly runs: JobRunCounter | undefined;
  private readonly clock: JobClock;
  private readonly random: () => number;
  private readonly shutdownTimeoutMs: number;

  /** The pending wake of each job. */
  private readonly timers = new Map<string, unknown>();
  /** Each job with an attempt in progress on this node, until its run has settled. */
  private readonly busy = new Map<string, Promise<void>>();
  /** The lock-holding part of every attempt in progress. */
  private readonly leased = new Set<Promise<void>>();
  /** Aborted by {@link stop}: runs are told to stop and holds end. */
  private readonly shutdown = new AbortController();
  /** Aborted when shutdown stops waiting for runs. */
  private readonly abandon = new AbortController();
  private state: 'created' | 'running' | 'stopped' = 'created';
  private stopping: Promise<void> | undefined;

  constructor(options: JobRunnerOptions) {
    const names = new Set<string>();
    for (const job of options.jobs) {
      if (names.has(job.name)) throw new Error(`Job "${job.name}" is defined twice`);
      names.add(job.name);
    }
    const shutdownTimeoutMs = options.shutdownTimeoutMs ?? JOB_SHUTDOWN_TIMEOUT_MS;
    if (!Number.isSafeInteger(shutdownTimeoutMs) || shutdownTimeoutMs < 0) {
      throw new Error('The job shutdown limit must be a whole number of milliseconds');
    }

    const roles = new Set<ServiceRole>(options.roles);
    this.active = options.jobs.filter((job) => roles.has(job.role));
    this.activeJobNames = Object.freeze(this.active.map((job) => job.name));
    this.lock = options.lock;
    this.log = options.log;
    this.runs = options.runs;
    this.clock = options.clock ?? systemClock;
    this.random = options.random ?? Math.random;
    this.shutdownTimeoutMs = shutdownTimeoutMs;
  }

  /**
   * Schedule every active job for its next slot.
   *
   * @throws When called twice, or after {@link stop}.
   */
  start(): void {
    if (this.state !== 'created') throw new Error('The job runner can be started once');
    this.state = 'running';
    for (const job of this.active) this.schedule(job);
    this.log.info({ jobs: this.activeJobNames }, 'job runner started');
  }

  /**
   * Stop scheduling, tell running jobs to stop, and wait for them up to the
   * shutdown limit. A job still running then is given up on: its lock is
   * released and this resolves. Safe to call more than once.
   */
  stop(): Promise<void> {
    this.stopping ??= this.stopGracefully();
    return this.stopping;
  }

  private async stopGracefully(): Promise<void> {
    const wasRunning = this.state === 'running';
    this.state = 'stopped';
    for (const timer of this.timers.values()) this.clock.clearTimeout(timer);
    this.timers.clear();
    this.shutdown.abort();

    if (this.busy.size > 0 && !(await this.allSettledWithin(this.shutdownTimeoutMs))) {
      this.log.warn(
        { jobs: [...this.busy.keys()], shutdownTimeoutMs: this.shutdownTimeoutMs },
        'jobs still running at the shutdown limit; releasing their locks'
      );
      this.abandon.abort();
      await Promise.allSettled([...this.leased]);
    }
    if (wasRunning) this.log.info('job runner stopped');
  }

  /** Whether every attempt in progress settles within `limitMs`. */
  private allSettledWithin(limitMs: number): Promise<boolean> {
    return new Promise((resolve) => {
      const timer = this.clock.setTimeout(() => resolve(false), limitMs);
      void Promise.allSettled([...this.busy.values()]).then(() => {
        this.clock.clearTimeout(timer);
        resolve(true);
      });
    });
  }

  /**
   * Arm the wake for the job's next slot: the first slot after now, and after
   * `previousSlotStart` when given, so a clock that steps back cannot wake a
   * node twice in one slot.
   */
  private schedule(job: JobDefinition, previousSlotStart?: number): void {
    const now = this.clock.now();
    let slotStart = (Math.floor(now / job.intervalMs) + 1) * job.intervalMs;
    if (previousSlotStart !== undefined) {
      slotStart = Math.max(slotStart, previousSlotStart + job.intervalMs);
    }
    const wakeAt = slotStart + Math.floor(this.random() * jitterWindowMs(job.intervalMs));
    const timer = this.clock.setTimeout(() => this.wake(job, slotStart), wakeAt - now);
    this.timers.set(job.name, timer);
  }

  private wake(job: JobDefinition, slotStart: number): void {
    this.timers.delete(job.name);
    if (this.state !== 'running') return;
    this.schedule(job, slotStart);

    if (this.busy.has(job.name)) {
      this.log.warn(
        { job: job.name },
        'job run skipped: its previous run on this node has not ended'
      );
      return;
    }
    const attempt = this.attempt(job, slotStart)
      .catch((error: unknown) => {
        this.log.error({ err: error, job: job.name }, 'job attempt failed unexpectedly');
      })
      .finally(() => {
        this.busy.delete(job.name);
      });
    this.busy.set(job.name, attempt);
  }

  /** Take the lock, run the job, hold the lock through the wake window, release it. */
  private async attempt(job: JobDefinition, slotStart: number): Promise<void> {
    const log = this.log.child({ job: job.name });

    let lease: JobLease | null;
    try {
      lease = await this.lock.tryAcquire(job.name);
    } catch (error) {
      log.error({ err: error }, 'job lock could not be taken; the run waits for the next interval');
      this.count(job, 'failure');
      return;
    }
    if (lease === null) {
      log.debug('job run skipped: another node holds its lock');
      return;
    }

    const held = lease;
    const holdUntil = slotStart + 2 * jitterWindowMs(job.intervalMs);
    let settled: Promise<void> | undefined;
    const leased = (async () => {
      try {
        if (this.shutdown.signal.aborted) return;
        // A node that got here after the slot's winner let go, because its
        // timer fired late or the lock took long to take, would run the slot
        // a second time. It leaves the slot to the next interval instead.
        if (this.clock.now() >= holdUntil) {
          log.warn('job run skipped: the lock was taken after its slot had closed');
          return;
        }
        ({ settled } = await this.execute(job, held, log));
        await this.hold(held, holdUntil);
      } finally {
        await held.release().catch((error: unknown) => {
          log.error({ err: error }, 'job lock could not be released');
        });
      }
    })();
    this.leased.add(leased);
    try {
      await leased;
    } finally {
      this.leased.delete(leased);
    }
    // A run given up on still blocks this job on this node until it settles.
    await settled;
  }

  /**
   * Run the job until it settles, reaches its time limit, loses its lock, or is
   * given up on at shutdown. `settled` resolves when the run itself does, which
   * is later for a run that ignored its signal.
   */
  private async execute(
    job: JobDefinition,
    lease: JobLease,
    log: FastifyBaseLogger
  ): Promise<{ settled: Promise<void> }> {
    const controller = new AbortController();
    const startedAt = this.clock.now();
    log.info('job run started');

    const settled = Promise.resolve()
      .then(() => job.run({ signal: controller.signal, now: () => this.clock.now(), log }))
      .then(
        (): RunOutcome => ({ kind: 'success' }),
        (error: unknown): RunOutcome => ({ kind: 'failure', error })
      );

    let limit: unknown;
    const removals: Array<() => void> = [];
    const stopped = new Promise<RunOutcome>((resolve) => {
      limit = this.clock.setTimeout(() => resolve({ kind: 'timeout' }), job.timeoutMs);
      removals.push(
        onAbort(lease.lost, () => resolve({ kind: 'lock_lost' })),
        onAbort(this.abandon.signal, () => resolve({ kind: 'abandoned' })),
        onAbort(this.shutdown.signal, () => controller.abort(new JobStoppedError('shutdown')))
      );
    });

    const outcome = await Promise.race([settled, stopped]);
    this.clock.clearTimeout(limit);
    for (const remove of removals) remove();
    const durationMs = this.clock.now() - startedAt;

    switch (outcome.kind) {
      case 'success':
        log.info({ durationMs }, 'job run finished');
        this.count(job, 'success');
        break;
      case 'failure':
        if (this.shutdown.signal.aborted) {
          log.warn({ err: outcome.error, durationMs }, 'job run ended at shutdown');
        } else {
          log.error({ err: outcome.error, durationMs }, 'job run failed');
          this.count(job, 'failure');
        }
        break;
      case 'timeout':
        controller.abort(new JobStoppedError('timeout'));
        log.error(
          { durationMs, timeoutMs: job.timeoutMs },
          'job run exceeded its time limit and was stopped'
        );
        this.count(job, 'timeout');
        break;
      case 'lock_lost':
        controller.abort(new JobStoppedError('lock_lost'));
        log.error({ durationMs }, 'job lock was lost during the run; the run was stopped');
        this.count(job, 'failure');
        break;
      case 'abandoned':
        log.warn({ durationMs }, 'job run outlasted the shutdown limit and was given up on');
        break;
    }

    return { settled: settled.then(() => undefined) };
  }

  /** Keep the lock until `until`, unless it is lost or the server shuts down first. */
  private async hold(lease: JobLease, until: number): Promise<void> {
    const remaining = until - this.clock.now();
    if (remaining <= 0 || lease.lost.aborted || this.shutdown.signal.aborted) return;
    await new Promise<void>((resolve) => {
      const removals: Array<() => void> = [];
      const timer = this.clock.setTimeout(done, remaining);
      function done(): void {
        for (const remove of removals) remove();
        resolve();
      }
      removals.push(
        () => this.clock.clearTimeout(timer),
        onAbort(lease.lost, done),
        onAbort(this.shutdown.signal, done)
      );
    });
  }

  private count(job: JobDefinition, result: JobRunResult): void {
    this.runs?.inc({ job: job.name, result });
  }
}
