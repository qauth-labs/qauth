import { DAY_MS } from '@qauth-labs/shared-validation';
import type { FastifyBaseLogger } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import {
  createEventRetentionJob,
  EVENT_RETENTION_INTERVAL_MS,
  EVENT_RETENTION_JOB_NAME,
  type EventRetentionStore,
  type RetentionRoute,
} from './event-retention';

const NOW = 1_800_000_000_000;
const REALM_A = '0192e000-0000-7000-8000-00000000000a';
const REALM_B = '0192e000-0000-7000-8000-00000000000b';
const FALLBACK = { userEventRetentionDays: 90, adminEventRetentionDays: 365 };

type Batch = Awaited<ReturnType<EventRetentionStore['deleteBatch']>>;

function done(deleted: number, more = false, extra: Partial<Batch> = {}): Batch {
  return { status: 'done', deleted, more, anchor: null, chainBreak: null, ...extra } as Batch;
}

function store(batches: Batch[], realms = [REALM_A]) {
  const queue = [...batches];
  return {
    realms: vi.fn(async () =>
      realms.map((realmId) => ({
        realmId,
        realmExists: true,
        userEventRetentionDays: 90,
        adminEventRetentionDays: 365,
      }))
    ),
    offeredThrough: vi.fn(async (realmId: string) => `position-of-${realmId}`),
    deleteBatch: vi.fn<EventRetentionStore['deleteBatch']>(async () => queue.shift() ?? done(0)),
  };
}

function context(signal = new AbortController().signal) {
  const log = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
  return { signal, now: () => NOW, log: log as unknown as FastifyBaseLogger, ...log };
}

function job(
  retention: ReturnType<typeof store>,
  routes: RetentionRoute[] = [],
  deleted = { inc: vi.fn() }
) {
  return createEventRetentionJob({
    retention: retention as unknown as EventRetentionStore,
    routes,
    fallback: FALLBACK,
    deleted,
    batchSize: 2,
  });
}

describe('event-retention (#536)', () => {
  it('runs hourly on the delivery role', () => {
    const definition = job(store([]));
    expect(definition.name).toBe(EVENT_RETENTION_JOB_NAME);
    expect(definition.role).toBe('delivery');
    expect(definition.intervalMs).toBe(EVENT_RETENTION_INTERVAL_MS);
  });

  it("deletes each category past its realm's retention, batch by batch, and counts it", async () => {
    const retention = store([done(2, true), done(1), done(2, true), done(0)]);
    const deleted = { inc: vi.fn() };
    const ctx = context();

    await job(retention, [], deleted).run(ctx);

    expect(retention.realms).toHaveBeenCalledWith(FALLBACK);
    expect(retention.offeredThrough).toHaveBeenCalledWith(REALM_A, { kinds: [], destinations: [] });
    expect(retention.deleteBatch.mock.calls.map(([request]) => request)).toEqual([
      ...[1, 2].map(() => ({
        realmId: REALM_A,
        category: 'user',
        before: NOW - 90 * DAY_MS,
        through: `position-of-${REALM_A}`,
        limit: 2,
        now: NOW,
      })),
      ...[1, 2].map(() => ({
        realmId: REALM_A,
        category: 'admin',
        before: NOW - 365 * DAY_MS,
        through: `position-of-${REALM_A}`,
        limit: 2,
        now: NOW,
      })),
    ]);
    expect(deleted.inc.mock.calls).toEqual([
      [{ category: 'user' }, 2],
      [{ category: 'user' }, 1],
      [{ category: 'admin' }, 2],
    ]);
    expect(ctx.info).toHaveBeenCalledWith(
      { deleted: { user: 3, admin: 2 }, realms: 1, busyRealms: 0 },
      'event retention ran'
    );
  });

  it('passes the enabled destinations of the routes that listed them', async () => {
    const retention = store([]);
    const ctx = context();
    const routes: RetentionRoute[] = [
      {
        kind: 'webhook',
        destinations: async () => [{ id: 'a', realmId: REALM_A, types: ['x'] }],
      },
      {
        kind: 'ssf',
        destinations: async () => {
          throw new Error('listing failed');
        },
      },
      {
        kind: 'odd',
        destinations: async () => [
          { id: 7, realmId: REALM_A } as unknown as { id: string; realmId: string },
        ],
      },
    ];

    await job(retention, routes).run(ctx);

    // The two routes that did not answer cleanly count in full.
    expect(retention.offeredThrough).toHaveBeenCalledWith(REALM_A, {
      kinds: ['webhook'],
      destinations: [{ kind: 'webhook', id: 'a', realmId: REALM_A }],
    });
    expect(ctx.warn).toHaveBeenCalledTimes(2);
  });

  it('leaves a realm another instance holds and goes on with the next', async () => {
    const retention = store([{ status: 'busy' }, done(1)], [REALM_A, REALM_B]);
    const ctx = context();

    await job(retention).run(ctx);

    expect(retention.deleteBatch.mock.calls.map(([request]) => request.realmId)).toEqual([
      REALM_A,
      REALM_B,
      REALM_B,
    ]);
    expect(ctx.info).toHaveBeenCalledWith(
      { deleted: { user: 1, admin: 0 }, realms: 2, busyRealms: 1 },
      'event retention ran'
    );
  });

  it('logs a chain break at the oldest admin event as an error', async () => {
    const retention = store([
      done(0),
      done(1, false, {
        chainBreak: { id: 'event-id', seq: 42n, reason: 'hash_mismatch' },
      } as Partial<Batch>),
    ]);
    const ctx = context();

    await job(retention).run(ctx);

    expect(ctx.error).toHaveBeenCalledWith(
      { realm: REALM_A, eventId: 'event-id', seq: '42', reason: 'hash_mismatch' },
      'the admin event chain breaks at its oldest event; retention keeps it and every later admin event'
    );
  });

  it('stops between batches once its signal is aborted', async () => {
    const controller = new AbortController();
    const retention = store([done(2, true), done(2, true)]);
    retention.deleteBatch.mockImplementationOnce(async () => {
      controller.abort(new Error('stop'));
      return done(2, true);
    });

    await expect(job(retention).run(context(controller.signal))).rejects.toThrow('stop');
    expect(retention.deleteBatch).toHaveBeenCalledOnce();
  });
});
