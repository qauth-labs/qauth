import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  createSessionExpiryJob,
  SESSION_EXPIRY_INTERVAL_MS,
  SESSION_EXPIRY_JOB_NAME,
  type SessionExpiryJobOptions,
} from './session-expiry';

function sessions() {
  return { endLapsed: vi.fn(async () => ({ ended: 4 })) };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn() };
  return { signal, now: () => 0, log: log as unknown as FastifyBaseLogger, info: log.info };
}

// The sweep's SQL is proved against Postgres in the repository's integration
// suite (each end, a millisecond before and at it); the container-backed
// `session-revocation.integration.test.ts` runs the job on the job runner.
describe('session-expiry (#550)', () => {
  it('runs every five minutes on the web role', () => {
    const job = createSessionExpiryJob({ sessions: sessions() });

    expect(job.name).toBe(SESSION_EXPIRY_JOB_NAME);
    expect(job.role).toBe('web');
    expect(job.intervalMs).toBe(SESSION_EXPIRY_INTERVAL_MS);
    expect(SESSION_EXPIRY_INTERVAL_MS).toBe(5 * 60_000);
  });

  it('marks the lapsed sessions, with the run’s signal, and logs how many', async () => {
    const service = sessions();
    const job = createSessionExpiryJob({ sessions: service });
    const ctx = context();

    await job.run(ctx);

    expect(service.endLapsed).toHaveBeenCalledExactlyOnceWith({ signal: ctx.signal });
    expect(ctx.info).toHaveBeenCalledWith({ ended: 4 }, 'lapsed sessions ended');
  });

  it('does nothing once its signal is aborted', async () => {
    const service = sessions();
    const controller = new AbortController();
    controller.abort(new Error('shutdown'));

    await expect(
      createSessionExpiryJob({ sessions: service }).run(context(controller.signal))
    ).rejects.toThrow('shutdown');
    expect(service.endLapsed).not.toHaveBeenCalled();
  });

  it('refuses to be built without the session service', () => {
    expect(() =>
      createSessionExpiryJob({ sessions: undefined } as SessionExpiryJobOptions)
    ).toThrow('fastify.sessionService');
  });
});
