import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  createSessionPurgeJob,
  DEFAULT_SESSION_RETENTION_DAYS,
  SESSION_PURGE_INTERVAL_MS,
  SESSION_PURGE_JOB_NAME,
  type SessionPurgeJobOptions,
} from './session-purge';

const NOW = 1_800_000_000_000;
const DAY = 24 * 60 * 60_000;

function sessions() {
  return { purge: vi.fn(async () => ({ deleted: 9 })) };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn() };
  return { signal, now: () => NOW, log: log as unknown as FastifyBaseLogger, info: log.info };
}

// The SQL is proved against Postgres in the repository's integration suite
// and the service's rules in its unit tests; the container-backed
// `session-revocation.integration.test.ts` runs the job on the job runner.
// This pins the job around them.
describe('session-purge (#550)', () => {
  it('runs hourly on the web role, keeping 30 days by default', () => {
    const job = createSessionPurgeJob({ sessions: sessions(), retentionDays: 30 });

    expect(job.name).toBe(SESSION_PURGE_JOB_NAME);
    expect(job.role).toBe('web');
    expect(job.intervalMs).toBe(SESSION_PURGE_INTERVAL_MS);
    expect(SESSION_PURGE_INTERVAL_MS).toBe(60 * 60_000);
    expect(DEFAULT_SESSION_RETENTION_DAYS).toBe(30);
  });

  it('deletes the rows that ended more than the retention ago', async () => {
    const service = sessions();
    const job = createSessionPurgeJob({ sessions: service, retentionDays: 7 });
    const ctx = context();

    await job.run(ctx);

    expect(service.purge).toHaveBeenCalledWith({ endedBefore: NOW - 7 * DAY, signal: ctx.signal });
    expect(ctx.info).toHaveBeenCalledWith({ deleted: 9 }, 'old sessions purged');
  });

  it('does nothing once its signal is aborted', async () => {
    const service = sessions();
    const controller = new AbortController();
    controller.abort(new Error('shutdown'));
    const job = createSessionPurgeJob({ sessions: service, retentionDays: 30 });

    await expect(job.run(context(controller.signal))).rejects.toThrow('shutdown');

    expect(service.purge).not.toHaveBeenCalled();
  });

  it('refuses to be built without the session service or with a retention that is not whole days', () => {
    expect(() =>
      createSessionPurgeJob({
        sessions: undefined,
        retentionDays: 30,
      } as unknown as SessionPurgeJobOptions)
    ).toThrow('fastify.sessionService');
    for (const retentionDays of [0, -1, 1.5, Number.NaN]) {
      expect(() => createSessionPurgeJob({ sessions: sessions(), retentionDays })).toThrow(
        'SESSION_RETENTION_DAYS'
      );
    }
  });
});
