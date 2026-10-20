import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  createPurgeExpiredJob,
  PURGE_EXPIRED_INTERVAL_MS,
  PURGE_EXPIRED_JOB_NAME,
  type PurgeExpiredRepositories,
} from './purge-expired';

function repositories() {
  return {
    authorizationCodes: { deleteExpired: vi.fn(async () => 2) },
    refreshTokens: { deleteExpired: vi.fn(async () => 3) },
    emailVerificationTokens: { deleteExpired: vi.fn(async () => [{ id: 'a' }]) },
    oid4vpRequestStates: { deleteExpired: vi.fn(async () => 4) },
  };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn() };
  return { signal, now: () => 0, log: log as unknown as FastifyBaseLogger, info: log.info };
}

describe('purge-expired', () => {
  it('runs hourly on the api role', () => {
    const job = createPurgeExpiredJob(repositories() as unknown as PurgeExpiredRepositories);

    expect(job.name).toBe(PURGE_EXPIRED_JOB_NAME);
    expect(job.role).toBe('api');
    expect(job.intervalMs).toBe(PURGE_EXPIRED_INTERVAL_MS);
  });

  it('deletes the expired rows of the four tables and logs how many', async () => {
    const repos = repositories();
    const job = createPurgeExpiredJob(repos as unknown as PurgeExpiredRepositories);
    const ctx = context();

    await job.run(ctx);

    for (const repository of Object.values(repos)) {
      expect(repository.deleteExpired).toHaveBeenCalledOnce();
    }
    expect(ctx.info).toHaveBeenCalledWith(
      {
        deleted: {
          authorization_codes: 2,
          refresh_tokens: 3,
          email_verification_tokens: 1,
          oid4vp_request_states: 4,
        },
      },
      'expired rows purged'
    );
  });

  it('stops between tables once its signal is aborted', async () => {
    const repos = repositories();
    const controller = new AbortController();
    repos.authorizationCodes.deleteExpired.mockImplementation(async () => {
      controller.abort(new Error('time limit'));
      return 0;
    });
    const job = createPurgeExpiredJob(repos as unknown as PurgeExpiredRepositories);

    await expect(job.run(context(controller.signal))).rejects.toThrow('time limit');

    expect(repos.refreshTokens.deleteExpired).not.toHaveBeenCalled();
    expect(repos.emailVerificationTokens.deleteExpired).not.toHaveBeenCalled();
    expect(repos.oid4vpRequestStates.deleteExpired).not.toHaveBeenCalled();
  });
});
