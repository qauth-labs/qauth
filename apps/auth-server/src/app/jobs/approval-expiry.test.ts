import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  APPROVAL_EXPIRY_BATCH,
  APPROVAL_EXPIRY_INTERVAL_MS,
  APPROVAL_EXPIRY_JOB_NAME,
  type ApprovalExpiryRepositories,
  createApprovalExpiryJob,
} from './approval-expiry';

const NOW = 1_800_000_000_000;

/** The repository, marking `batches[i]` approvals on its i-th call. */
function repositories(...batches: number[]) {
  const expireLapsed = vi.fn<(now: number, limit: number) => Promise<number>>();
  for (const marked of batches) expireLapsed.mockResolvedValueOnce(marked);
  expireLapsed.mockResolvedValue(0);
  return { adminApprovals: { expireLapsed } };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn() };
  return { signal, now: () => NOW, log: log as unknown as FastifyBaseLogger, info: log.info };
}

const job = (repos: ReturnType<typeof repositories>) =>
  createApprovalExpiryJob(repos as unknown as ApprovalExpiryRepositories);

// What the repository marks, and that it overwrites the nonce, is proved
// against Postgres in `admin-approvals.integration.test.ts`. This pins the
// job around it.
describe('approval-expiry (#901)', () => {
  it('runs every minute on the admin role', () => {
    const defined = job(repositories());

    expect(defined.name).toBe(APPROVAL_EXPIRY_JOB_NAME);
    expect(defined.role).toBe('admin');
    expect(defined.intervalMs).toBe(APPROVAL_EXPIRY_INTERVAL_MS);
    expect(APPROVAL_EXPIRY_INTERVAL_MS).toBe(60_000);
  });

  it('marks at the runner’s time, batch after batch until one comes back short', async () => {
    const repos = repositories(APPROVAL_EXPIRY_BATCH, APPROVAL_EXPIRY_BATCH, 3);
    const ctx = context();

    await job(repos).run(ctx);

    expect(repos.adminApprovals.expireLapsed).toHaveBeenCalledTimes(3);
    for (const call of repos.adminApprovals.expireLapsed.mock.calls) {
      expect(call).toEqual([NOW, APPROVAL_EXPIRY_BATCH]);
    }
    expect(ctx.info).toHaveBeenCalledWith(
      { expired: 2 * APPROVAL_EXPIRY_BATCH + 3 },
      'expired approvals retired'
    );
  });

  it('marks nothing once its signal is aborted', async () => {
    const repos = repositories();
    const controller = new AbortController();
    controller.abort(new Error('shutdown'));

    await expect(job(repos).run(context(controller.signal))).rejects.toThrow('shutdown');

    expect(repos.adminApprovals.expireLapsed).not.toHaveBeenCalled();
  });
});
