import type { EventEnvelope } from '@qauth-labs/shared-events';
import { createManualClock, type ManualClock } from '@qauth-labs/shared-testing';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createMemoryStore, type MemoryStore } from '../testing/memory-store';
import {
  DEFAULT_DELIVERY_SETTINGS,
  type DeliveryRole,
  type DeliveryRoleOptions,
  resolveDeliverySettings,
  startDeliveryRole,
} from './delivery-role';
import type {
  Delivery,
  DeliveryContext,
  DeliveryOutcome,
  DeliveryRoute,
  DeliverySigner,
  RouteDestination,
} from './types';

/**
 * The delivery role's own logic (issue #460) against a store in memory: what
 * it fans out, how it hands out its slots, retries and gives up, and how it
 * stops. The container suites of `@qauth-labs/fastify-plugin-event-delivery`
 * run it against Postgres.
 */

const REALM = '01920000-0000-7000-8000-000000000001';
const OTHER_REALM = '01920000-0000-7000-8000-000000000002';
const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
const SIGNED_OUT = 'urn:qauth:event:user.signed_out:v1-rc.0';
const START = 1_800_000_000_000;
const POLL = 1_000;

let counter = 0;
function envelope(realm = REALM, type = SIGNED_IN): EventEnvelope {
  counter += 1;
  return {
    id: `01920000-0000-7000-8000-${String(counter).padStart(12, '0')}`,
    type,
    time: new Date(START).toISOString(),
    realm,
    category: 'user',
    data: {},
  } as EventEnvelope;
}

interface Call {
  readonly delivery: Delivery;
  readonly event: EventEnvelope;
  readonly context: DeliveryContext;
  readonly at: number;
}

/** A route of kind `test` that records each call and answers with `answer`. */
function route(
  clock: ManualClock,
  destinations: RouteDestination[] | (() => Promise<RouteDestination[]>),
  answer: (
    delivery: Delivery,
    call: number
  ) => Promise<DeliveryOutcome> | DeliveryOutcome = () => ({
    ok: true,
    statusCode: 200,
  }),
  kind = 'test'
): DeliveryRoute & { calls: Call[] } {
  const calls: Call[] = [];
  return {
    kind,
    calls,
    destinations: typeof destinations === 'function' ? destinations : async () => destinations,
    async deliver(delivery, event, context) {
      calls.push({ delivery, event, context, at: clock.now() });
      return answer(delivery, calls.length);
    },
  };
}

const signer: DeliverySigner = {
  signWebhook: async () => 'v1,signature',
  signEventToken: async () => 'header.payload.signature',
};

function logger() {
  return { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

const roles: Array<{ role: DeliveryRole; clock: ManualClock }> = [];

afterEach(async () => {
  // A route that never answers holds stop() until the shutdown limit passes.
  await Promise.all(
    roles.splice(0).map(async ({ role, clock }) => {
      const stopped = role.stop();
      await clock.advanceBy(role.settings.shutdownTimeoutMs);
      await stopped;
    })
  );
});

interface Setup {
  clock: ManualClock;
  store: MemoryStore;
  log: ReturnType<typeof logger>;
  attempts: Array<{ kind: string; result: string }>;
  role: DeliveryRole;
}

/** Start a role and let its first cycle give each realm its position. */
async function setup(
  routes: (clock: ManualClock) => DeliveryRoute[],
  options: Partial<DeliveryRoleOptions> = {},
  waitForFanOut = true
): Promise<Setup & { routes: DeliveryRoute[] }> {
  const clock = createManualClock(START);
  const store = createMemoryStore();
  const log = logger();
  const attempts: Array<{ kind: string; result: string }> = [];
  const list = routes(clock);
  const role = startDeliveryRole({
    store,
    routes: list,
    signer,
    log,
    metrics: { attempt: (kind, result) => attempts.push({ kind, result }) },
    clock,
    random: () => 0,
    ...options,
  });
  roles.push({ role, clock });
  await clock.advanceBy(0);
  if (waitForFanOut) await vi.waitFor(() => expect(store.calls.fanOut).toBeGreaterThan(0));
  return { clock, store, log, attempts, role, routes: list };
}

describe('startDeliveryRole', () => {
  it('delivers each new event to each matching destination, with the event id', async () => {
    let all!: ReturnType<typeof route>;
    const { clock, store } = await setup((clock) => {
      all = route(clock, [
        { id: 'everything', realmId: REALM },
        { id: 'sign-outs', realmId: REALM, types: [SIGNED_OUT] },
        { id: 'admin', realmId: REALM, categories: ['admin'] },
        { id: 'elsewhere', realmId: OTHER_REALM },
      ]);
      return [all];
    });
    const signIn = envelope();
    const signOut = envelope(REALM, SIGNED_OUT);
    store.append(signIn);
    store.append(signOut);
    await clock.advanceBy(POLL);

    await vi.waitFor(() =>
      expect(store.rows.every((row) => row.status === 'delivered')).toBe(true)
    );
    expect(
      all.calls.map((call) => [call.delivery.destinationId, call.delivery.eventId, call.event.id])
    ).toEqual(
      expect.arrayContaining([
        ['everything', signIn.id, signIn.id],
        ['everything', signOut.id, signOut.id],
        ['sign-outs', signOut.id, signOut.id],
      ])
    );
    expect(all.calls).toHaveLength(3);
    expect(all.calls[0].context.signer).toBe(signer);
    expect(all.calls[0].delivery).toMatchObject({
      realmId: REALM,
      attempt: 1,
      destinationKind: 'test',
    });
  });

  it('retries with growing delays and ends delivered', async () => {
    let flaky!: ReturnType<typeof route>;
    const { clock, store, attempts } = await setup(
      (clock) => {
        flaky = route(clock, [{ id: 'flaky', realmId: REALM }], (_delivery, call) =>
          call <= 3
            ? { ok: false, errorClass: 'http_status', statusCode: 503 }
            : { ok: true, statusCode: 204 }
        );
        return [flaky];
      },
      {
        settings: {
          retry: { initialDelayMs: 10_000, maxDelayMs: 600_000, multiplier: 2, jitter: 0.2 },
        },
      }
    );
    store.append(envelope());
    await clock.advanceBy(POLL);
    await vi.waitFor(() => expect(flaky.calls).toHaveLength(1));
    for (let i = 0; i < 6; i += 1) await clock.advanceBy(20_000);
    await vi.waitFor(() => expect(store.rows[0].status).toBe('delivered'));

    const at = flaky.calls.map((call) => call.at);
    const gaps = at.slice(1).map((time, i) => time - at[i]);
    expect(gaps).toHaveLength(3);
    expect(gaps[1]).toBeGreaterThan(gaps[0]);
    expect(gaps[2]).toBeGreaterThan(gaps[1]);
    expect(gaps[0]).toBeGreaterThanOrEqual(10_000);
    expect(store.rows[0]).toMatchObject({ attempt: 4, lastStatusCode: 204, lastErrorClass: null });
    expect(attempts.map((attempt) => attempt.result)).toEqual([
      'retry',
      'retry',
      'retry',
      'delivered',
    ]);
  });

  it('ends failed after the last attempt, and keeps the row', async () => {
    let down!: ReturnType<typeof route>;
    const { clock, store, attempts, log } = await setup(
      (clock) => {
        down = route(clock, [{ id: 'down', realmId: REALM }], () => ({
          ok: false,
          errorClass: 'connect_failed',
        }));
        return [down];
      },
      { settings: { maxAttempts: 3, retry: { initialDelayMs: 1_000, maxDelayMs: 1_000 } } }
    );
    store.append(envelope());
    await clock.advanceBy(POLL);
    for (let i = 0; i < 10; i += 1) await clock.advanceBy(1_000);
    await vi.waitFor(() => expect(store.rows[0].status).toBe('failed'));

    expect(down.calls).toHaveLength(3);
    expect(store.rows[0]).toMatchObject({ attempt: 3, lastErrorClass: 'connect_failed' });
    expect(attempts.map((attempt) => attempt.result)).toEqual(['retry', 'retry', 'failed']);
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ destinationId: 'down', errorClass: 'connect_failed', attempt: 3 }),
      'event delivery failed for good'
    );
  });

  it('ends failed at once on a refusal the route marks final', async () => {
    let gone!: ReturnType<typeof route>;
    const { clock, store } = await setup((clock) => {
      gone = route(clock, [{ id: 'gone', realmId: REALM }], () => ({
        ok: false,
        errorClass: 'destination_gone',
        statusCode: 410,
        retry: false,
      }));
      return [gone];
    });
    store.append(envelope());
    await clock.advanceBy(POLL);
    await vi.waitFor(() => expect(store.rows[0].status).toBe('failed'));
    expect(gone.calls).toHaveLength(1);
    expect(store.rows[0]).toMatchObject({
      lastStatusCode: 410,
      lastErrorClass: 'destination_gone',
    });
  });

  it.each([
    ['throws', () => Promise.reject(new Error('boom'))],
    ['returns no outcome', () => Promise.resolve(undefined as unknown as DeliveryOutcome)],
    [
      'gives a message as its error class',
      () => Promise.resolve({ ok: false, errorClass: 'It broke: token=abc' } as DeliveryOutcome),
    ],
  ])('records route_error and retries when the route %s', async (_label, answer) => {
    const { clock, store } = await setup((clock) => [
      route(clock, [{ id: 'a', realmId: REALM }], answer),
    ]);
    store.append(envelope());
    await clock.advanceBy(POLL);
    await vi.waitFor(() => expect(store.rows[0].lastErrorClass).toBe('route_error'));
    expect(store.rows[0].status).toBe('pending');
  });

  it('stops waiting at the time limit, records timeout, and retries', async () => {
    let hanging!: ReturnType<typeof route>;
    const { clock, store } = await setup(
      (clock) => {
        // Ignores its signal and never answers.
        hanging = route(
          clock,
          [{ id: 'hangs', realmId: REALM }],
          () => new Promise<DeliveryOutcome>(() => undefined)
        );
        return [hanging];
      },
      { settings: { attemptTimeoutMs: 5_000 } }
    );
    store.append(envelope());
    await clock.advanceBy(POLL);
    await vi.waitFor(() => expect(hanging.calls).toHaveLength(1));
    await clock.advanceBy(5_000);
    await vi.waitFor(() => expect(store.rows[0].lastErrorClass).toBe('timeout'));
    expect(hanging.calls[0].context.signal.aborted).toBe(true);
    expect(store.rows[0].status).toBe('pending');
  });

  it('keeps a hanging destination to its share of the slots, so another is delivered at once', async () => {
    let both!: ReturnType<typeof route>;
    const { clock, store } = await setup(
      (clock) => {
        both = route(
          clock,
          [
            { id: 'a-stalled', realmId: REALM },
            { id: 'b-healthy', realmId: REALM },
          ],
          (delivery) =>
            delivery.destinationId === 'a-stalled'
              ? new Promise<DeliveryOutcome>(() => undefined)
              : { ok: true, statusCode: 200 }
        );
        return [both];
      },
      { settings: { concurrency: 4, maxInFlightPerDestination: 2, attemptTimeoutMs: 50_000 } }
    );
    for (let i = 0; i < 10; i += 1) store.append(envelope());
    await clock.advanceBy(POLL);

    await vi.waitFor(() =>
      expect(
        store.rows.filter((row) => row.destinationId === 'b-healthy' && row.status === 'delivered')
      ).toHaveLength(10)
    );
    // No time passed: the healthy destination did not wait for the stalled one.
    expect(clock.now()).toBe(START + POLL);
    const stalled = both.calls.filter((call) => call.delivery.destinationId === 'a-stalled');
    expect(stalled).toHaveLength(2);
  });

  it('fans out nothing while a route cannot list its destinations', async () => {
    let failing = true;
    const listing = vi.fn(async () => {
      if (failing) throw new Error('listing failed');
      return [{ id: 'a', realmId: REALM }];
    });
    let other!: ReturnType<typeof route>;
    const { clock, store, log } = await setup(
      (clock) => {
        other = route(clock, [{ id: 'b', realmId: REALM }], undefined, 'other');
        return [route(clock, listing), other];
      },
      {},
      false
    );
    await vi.waitFor(() => expect(listing).toHaveBeenCalled());
    expect(store.calls.fanOut).toBe(0);
    expect(log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ kind: 'test' }),
      'a delivery route could not list its destinations; nothing is fanned out this cycle'
    );

    failing = false;
    await clock.advanceBy(POLL);
    await vi.waitFor(() => expect(store.calls.fanOut).toBe(1));
    store.append(envelope());
    await clock.advanceBy(POLL);
    await vi.waitFor(() =>
      expect(store.rows.map((row) => row.destinationId).sort()).toEqual(['a', 'b'])
    );
  });

  it('leaves out a malformed destination and says so once', async () => {
    const { clock, store, log } = await setup((clock) => [
      route(clock, [
        { id: 'ok', realmId: REALM },
        { id: '', realmId: REALM },
        { id: 'bad-realm', realmId: 'not-a-uuid' },
      ]),
    ]);
    store.append(envelope());
    await clock.advanceBy(POLL);
    await clock.advanceBy(POLL);
    await vi.waitFor(() => expect(store.rows.map((row) => row.destinationId)).toEqual(['ok']));
    const malformed = log.warn.mock.calls.filter(
      ([, message]) =>
        message === 'a delivery route listed a malformed destination; it receives nothing'
    );
    expect(malformed).toHaveLength(2);
  });

  it('fails an event the store cannot read, without calling the route', async () => {
    let unread!: ReturnType<typeof route>;
    const { clock, store } = await setup((clock) => {
      unread = route(clock, [{ id: 'a', realmId: REALM }]);
      return [unread];
    });
    store.rows.push({
      id: 'delivery-unreadable',
      kind: 'test',
      destinationId: 'a',
      event: null,
      eventId: envelope().id,
      realmId: REALM,
      status: 'pending',
      attempt: 0,
      nextAttemptAt: 0,
      lockedUntil: null,
      lastStatusCode: null,
      lastErrorClass: null,
    });
    await clock.advanceBy(POLL);
    await vi.waitFor(() => expect(store.rows[0].status).toBe('failed'));
    expect(store.rows[0]).toMatchObject({ attempt: 1, lastErrorClass: 'unreadable_event' });
    expect(unread.calls).toHaveLength(0);
  });

  it('with no route, clears the positions once and claims nothing', async () => {
    const { clock, store } = await setup(() => []);
    await clock.advanceBy(POLL * 5);
    expect(store.calls.fanOut).toBe(1);
    expect(store.calls.claim).toBe(0);
  });

  describe('stop', () => {
    it('claims nothing more and lets an attempt in flight finish', async () => {
      let answer!: (outcome: DeliveryOutcome) => void;
      let slow!: ReturnType<typeof route>;
      const { clock, store, role } = await setup(
        (clock) => {
          slow = route(
            clock,
            [{ id: 'slow', realmId: REALM }],
            () => new Promise<DeliveryOutcome>((resolve) => (answer = resolve))
          );
          return [slow];
        },
        { settings: { concurrency: 1, maxInFlightPerDestination: 1 } }
      );
      store.append(envelope());
      store.append(envelope());
      await clock.advanceBy(POLL);
      await vi.waitFor(() => expect(slow.calls).toHaveLength(1));

      const stopped = role.stop();
      answer({ ok: true, statusCode: 200 });
      await stopped;
      expect(store.rows.map((row) => row.status)).toEqual(['delivered', 'pending']);
      expect(slow.calls).toHaveLength(1);
      await clock.advanceBy(POLL * 10);
      expect(slow.calls).toHaveLength(1);
      expect(store.calls.release).toBe(0);
    });

    it('aborts and releases what is still running at the shutdown limit', async () => {
      let stuck!: ReturnType<typeof route>;
      const { clock, store, role, log } = await setup(
        (clock) => {
          stuck = route(
            clock,
            [{ id: 'stuck', realmId: REALM }],
            () => new Promise<DeliveryOutcome>(() => undefined)
          );
          return [stuck];
        },
        { settings: { shutdownTimeoutMs: 2_000, attemptTimeoutMs: 50_000 } }
      );
      store.append(envelope());
      await clock.advanceBy(POLL);
      await vi.waitFor(() => expect(stuck.calls).toHaveLength(1));

      const stopped = role.stop();
      await clock.advanceBy(2_000);
      await stopped;
      expect(stuck.calls[0].context.signal.aborted).toBe(true);
      expect(store.rows[0]).toMatchObject({
        status: 'pending',
        attempt: 1,
        lockedUntil: null,
        nextAttemptAt: START + POLL + 2_000,
        lastErrorClass: 'attempt_interrupted',
      });
      expect(log.warn).toHaveBeenCalledWith(
        expect.objectContaining({ deliveries: 1 }),
        'event deliveries still running at the shutdown limit were released'
      );
    });

    it('is safe to call twice', async () => {
      const { role } = await setup((clock) => [route(clock, [])]);
      await Promise.all([role.stop(), role.stop()]);
    });
  });
});

describe('resolveDeliverySettings', () => {
  it('fills in the defaults', () => {
    expect(resolveDeliverySettings()).toEqual(DEFAULT_DELIVERY_SETTINGS);
    expect(resolveDeliverySettings({ retry: { initialDelayMs: 5_000 } }).retry).toEqual({
      ...DEFAULT_DELIVERY_SETTINGS.retry,
      initialDelayMs: 5_000,
    });
  });

  it.each([
    ['an attempt that may outlive its lease', { leaseMs: 10_000, attemptTimeoutMs: 10_000 }],
    ['no attempt', { maxAttempts: 0 }],
    ['more per destination than in all', { concurrency: 2, maxInFlightPerDestination: 3 }],
    ['a page over 1000', { fanOutPageSize: 1001 }],
  ])('refuses %s', (_label, settings) => {
    expect(() => resolveDeliverySettings(settings)).toThrow(TypeError);
  });

  it('refuses two routes of one kind, and a kind that is not lower case', () => {
    const clock = createManualClock(START);
    const options = { store: createMemoryStore(), signer, log: logger(), clock };
    expect(() =>
      startDeliveryRole({ ...options, routes: [route(clock, []), route(clock, [])] })
    ).toThrow(TypeError);
    expect(() =>
      startDeliveryRole({ ...options, routes: [route(clock, [], undefined, 'Webhook')] })
    ).toThrow(TypeError);
  });
});
