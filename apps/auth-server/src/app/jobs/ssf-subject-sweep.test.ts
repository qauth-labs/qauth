import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  createSsfSubjectSweepJob,
  SSF_SUBJECT_SWEEP_INTERVAL_MS,
  SSF_SUBJECT_SWEEP_JOB_NAME,
  type SsfSubjectSweepRepositories,
} from './ssf-subject-sweep';

const NOW = 1_800_000_000_000;

function repositories(deleted = 3) {
  return { ssfStreams: { sweepUserSubjects: vi.fn(async () => deleted) } };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn() };
  return { signal, now: () => NOW, log: log as unknown as FastifyBaseLogger, info: log.info };
}

// The selection itself is one SQL statement (`sweepUserSubjects`), proved
// against Postgres in `ssf-streams.integration.test.ts`: a related user, an
// event not fanned out yet and a pending delivery each keep a subject. This
// pins the job around it.
describe('ssf-subject-sweep (#540)', () => {
  it('runs hourly on the api role', () => {
    const job = createSsfSubjectSweepJob(repositories() as unknown as SsfSubjectSweepRepositories);

    expect(job.name).toBe(SSF_SUBJECT_SWEEP_JOB_NAME);
    expect(job.role).toBe('api');
    expect(job.intervalMs).toBe(SSF_SUBJECT_SWEEP_INTERVAL_MS);
    expect(SSF_SUBJECT_SWEEP_INTERVAL_MS).toBe(60 * 60_000);
  });

  it('sweeps at the runner’s time and logs how many subjects ended', async () => {
    const repos = repositories(2);
    const job = createSsfSubjectSweepJob(repos as unknown as SsfSubjectSweepRepositories);
    const ctx = context();

    await job.run(ctx);

    expect(repos.ssfStreams.sweepUserSubjects).toHaveBeenCalledExactlyOnceWith(NOW);
    expect(ctx.info).toHaveBeenCalledWith({ deleted: 2 }, 'unrelated SSF user subjects ended');
  });

  it('deletes nothing once its signal is aborted', async () => {
    const repos = repositories();
    const controller = new AbortController();
    controller.abort(new Error('shutdown'));
    const job = createSsfSubjectSweepJob(repos as unknown as SsfSubjectSweepRepositories);

    await expect(job.run(context(controller.signal))).rejects.toThrow('shutdown');

    expect(repos.ssfStreams.sweepUserSubjects).not.toHaveBeenCalled();
  });
});
