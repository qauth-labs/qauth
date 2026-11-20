import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  createWebhookSecretOverlapJob,
  WEBHOOK_SECRET_OVERLAP_BATCH,
  WEBHOOK_SECRET_OVERLAP_INTERVAL_MS,
  WEBHOOK_SECRET_OVERLAP_JOB_NAME,
  type WebhookSecretOverlapJobDependencies,
} from './webhook-secret-overlap';

const NOW = 1_800_000_000_000;
const REALM = '018f0000-0000-7000-8000-000000000001';
const TX = { tx: true };

const overlap = (index: number) => ({
  realmId: REALM,
  id: `018f0000-0000-7000-8000-${String(index).padStart(12, '0')}`,
  previousSecretExpiresAt: NOW - 1000 - index,
});

/** The dependencies, listing `batches[i]` on the i-th read. */
function dependencies(...batches: ReturnType<typeof overlap>[][]) {
  const listEndedSecretOverlaps =
    vi.fn<WebhookSecretOverlapJobDependencies['subscriptions']['listEndedSecretOverlaps']>();
  for (const batch of batches) listEndedSecretOverlaps.mockResolvedValueOnce(batch);
  listEndedSecretOverlaps.mockResolvedValue([]);
  const endSecretOverlap = vi
    .fn<WebhookSecretOverlapJobDependencies['subscriptions']['endSecretOverlap']>()
    .mockResolvedValue(true);
  const endOverlap = vi
    .fn<NonNullable<WebhookSecretOverlapJobDependencies['secrets']>['endOverlap']>()
    .mockResolvedValue({ retiredKid: 'old' });
  const order: string[] = [];
  endSecretOverlap.mockImplementation(async () => {
    order.push('row');
    return true;
  });
  endOverlap.mockImplementation(async () => {
    order.push('keys');
    return { retiredKid: 'old' };
  });
  const transaction = vi.fn(async (work: (tx: never) => Promise<unknown>) =>
    work(TX as never)
  ) as unknown as WebhookSecretOverlapJobDependencies['transaction'];
  return {
    deps: {
      secrets: { endOverlap },
      subscriptions: { listEndedSecretOverlaps, endSecretOverlap },
      transaction,
    } satisfies WebhookSecretOverlapJobDependencies,
    listEndedSecretOverlaps,
    endSecretOverlap,
    endOverlap,
    order,
  };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn(), warn: vi.fn() };
  return {
    signal,
    now: () => NOW,
    log: log as unknown as FastifyBaseLogger,
    info: log.info,
    warn: log.warn,
  };
}

// What the repository and the key store change is proved against Postgres in
// `admin-webhooks.integration.test.ts` and the signer plugin's own suite.
// This pins the job around them.
describe('webhook-secret-overlap (#537)', () => {
  it('runs every minute on the signer role', () => {
    const job = createWebhookSecretOverlapJob(dependencies().deps);
    expect(job.name).toBe(WEBHOOK_SECRET_OVERLAP_JOB_NAME);
    expect(job.role).toBe('signer');
    expect(job.intervalMs).toBe(WEBHOOK_SECRET_OVERLAP_INTERVAL_MS);
    expect(WEBHOOK_SECRET_OVERLAP_INTERVAL_MS).toBe(60_000);
  });

  it('refuses to be built where no signer holds the secrets', () => {
    const { deps } = dependencies();
    expect(() => createWebhookSecretOverlapJob({ ...deps, secrets: null })).toThrow(
      'fastify.webhookSecrets'
    );
  });

  it('clears the row, then switches the keys, in one transaction per subscription', async () => {
    const due = [overlap(1), overlap(2)];
    const fake = dependencies(due);
    const ctx = context();

    await createWebhookSecretOverlapJob(fake.deps).run(ctx);

    expect(fake.listEndedSecretOverlaps).toHaveBeenCalledWith(NOW, WEBHOOK_SECRET_OVERLAP_BATCH);
    expect(fake.deps.transaction).toHaveBeenCalledTimes(2);
    expect(fake.endSecretOverlap.mock.calls).toEqual(
      due.map((entry) => [entry.realmId, entry.id, entry.previousSecretExpiresAt, TX])
    );
    expect(fake.endOverlap.mock.calls).toEqual(
      due.map((entry) => [{ realmId: entry.realmId, subscriptionId: entry.id, tx: TX }])
    );
    expect(fake.order).toEqual(['row', 'keys', 'row', 'keys']);
    expect(ctx.info).toHaveBeenCalledWith({ ended: 2, failed: 0 }, 'webhook secret overlaps ended');
  });

  it('leaves the keys of a subscription a rotation moved meanwhile', async () => {
    const fake = dependencies([overlap(1)]);
    fake.endSecretOverlap.mockImplementation(async () => false);
    const ctx = context();

    await createWebhookSecretOverlapJob(fake.deps).run(ctx);

    expect(fake.endOverlap).not.toHaveBeenCalled();
    expect(ctx.info).toHaveBeenCalledWith({ ended: 0, failed: 0 }, 'webhook secret overlaps ended');
  });

  it('logs a subscription that fails, goes on with the others, and does not retry it in the run', async () => {
    const failing = overlap(1);
    const batch = Array.from({ length: WEBHOOK_SECRET_OVERLAP_BATCH }, (_, index) =>
      overlap(index + 1)
    );
    // The first batch is full, so the job reads again; the read lists the
    // failed subscription again, first, and nothing else.
    const fake = dependencies(batch, [failing]);
    fake.endOverlap.mockImplementation(async (input) => {
      if (input.subscriptionId === failing.id) throw new Error('key store down');
      return { retiredKid: 'old' };
    });
    const ctx = context();

    await createWebhookSecretOverlapJob(fake.deps).run(ctx);

    expect(fake.listEndedSecretOverlaps).toHaveBeenCalledTimes(2);
    expect(fake.endOverlap).toHaveBeenCalledTimes(WEBHOOK_SECRET_OVERLAP_BATCH);
    expect(ctx.warn).toHaveBeenCalledTimes(1);
    expect(ctx.warn.mock.calls[0]?.[0]).toMatchObject({ subscriptionId: failing.id });
    expect(ctx.info).toHaveBeenCalledWith(
      { ended: WEBHOOK_SECRET_OVERLAP_BATCH - 1, failed: 1 },
      'webhook secret overlaps ended'
    );
  });

  it('ends nothing once its signal is aborted', async () => {
    const fake = dependencies([overlap(1)]);
    const controller = new AbortController();
    controller.abort();

    await expect(
      createWebhookSecretOverlapJob(fake.deps).run(context(controller.signal))
    ).rejects.toThrow();
    expect(fake.endSecretOverlap).not.toHaveBeenCalled();
  });
});
