import Fastify, { type FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { createManualClock } from '../../testing/manual-clock';
import { defineJob, type JobLease, type JobLock, type JobSpec } from '../jobs';
import { jobsPlugin, type JobsPluginOptions } from './jobs';
import { metricsPlugin } from './metrics';

const INTERVAL = 60_000;

/** A lock nobody else contends for. */
function soleLock(): JobLock & { held: Set<string> } {
  const held = new Set<string>();
  return {
    held,
    async tryAcquire(jobName: string): Promise<JobLease | null> {
      held.add(jobName);
      return {
        lost: new AbortController().signal,
        release: async () => {
          held.delete(jobName);
        },
      };
    },
  };
}

function job(run: JobSpec['run']) {
  return defineJob({ name: 'test-job', role: 'api', intervalMs: INTERVAL, run });
}

async function build(options: JobsPluginOptions): Promise<FastifyInstance> {
  const app = Fastify({ logger: false });
  await app.register(metricsPlugin);
  await app.register(jobsPlugin, options);
  return app;
}

describe('jobs plugin', () => {
  it('starts the runner when the server is ready and counts runs in the metrics', async () => {
    const clock = createManualClock();
    const run = vi.fn(async () => undefined);
    const app = await build({ jobs: [job(run)], lock: soleLock(), clock, random: () => 0 });

    expect(clock.pending()).toEqual([]);
    await app.ready();
    expect(clock.pending()).toEqual([INTERVAL]);

    await clock.advanceTo(INTERVAL);
    expect(run).toHaveBeenCalledOnce();
    const metrics = await app.metrics.registry.getSingleMetricAsString('qauth_job_runs_total');
    expect(metrics).toContain('job="test-job"');
    expect(metrics).toContain('result="success"');

    await app.close();
  });

  it('starts nothing for a role this node does not hold', async () => {
    const clock = createManualClock();
    const app = await build({
      jobs: [job(async () => undefined)],
      roles: ['signer'],
      lock: soleLock(),
      clock,
    });

    await app.ready();
    expect(clock.pending()).toEqual([]);
    await app.close();
  });

  it('waits on close for a running job up to the shutdown limit, then closes', async () => {
    const clock = createManualClock();
    const lock = soleLock();
    let signal: AbortSignal | undefined;
    const app = await build({
      jobs: [
        job((context) => {
          signal = context.signal;
          return new Promise<void>(() => undefined);
        }),
      ],
      lock,
      clock,
      random: () => 0,
      shutdownTimeoutMs: 1_000,
    });
    await app.ready();
    await clock.advanceTo(INTERVAL);
    expect(lock.held.has('test-job')).toBe(true);

    let closed = false;
    const closing = app.close().then(() => {
      closed = true;
    });
    await clock.advanceBy(999);
    expect(signal?.aborted).toBe(true);
    expect(closed).toBe(false);

    await clock.advanceBy(1);
    await closing;
    expect(lock.held.has('test-job')).toBe(false);
  });

  it('refuses to register without the database plugin when it needs the defaults', async () => {
    await expect(build({ jobs: [job(async () => undefined)] })).rejects.toThrow(
      /needs `fastify.dbPool`/
    );
    await expect(build({ lock: soleLock() })).rejects.toThrow(/needs `fastify.repositories`/);
  });
});
