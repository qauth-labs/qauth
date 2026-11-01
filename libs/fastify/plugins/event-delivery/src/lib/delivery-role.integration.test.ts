/**
 * THE DELIVERY ROLE AGAINST A REAL POSTGRES (ADR-019 Decision 8, issue #460).
 *
 * The acceptance criteria of #460, each against the migrated schema, with
 * workers that have their own connection pools as nodes would, and a test
 * receiver over HTTP that records every request it gets:
 *
 * - a worker that dies after it claimed an event and before it recorded
 *   success: a second worker delivers the same event again, and the
 *   receiver sees the duplicate with an equal id;
 * - two workers on one database deliver each event to each destination
 *   once, and never zero times;
 * - on a fake clock, a destination that fails three times and then succeeds
 *   is retried with growing delays and ends `delivered`; one that keeps
 *   failing ends `failed` after the last attempt and stays queryable;
 * - with one destination down, a second one receives every event without
 *   waiting for it;
 * - the plugin's metrics: the pending deliveries and the lag grow while a
 *   route is failing.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */
import { randomUUID } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';

import {
  createDatabase,
  createEventDeliveriesRepository,
  createEventsRepository,
  type DatabaseInstance,
  type EmitEvent,
} from '@qauth-labs/infra-db';
import {
  type DeliveryRole,
  type DeliveryRoute,
  type DeliverySettingsInput,
  type DeliverySigner,
  type RouteDestination,
  startDeliveryRole,
} from '@qauth-labs/server-event-delivery';
import type { Signer } from '@qauth-labs/server-keys';
import {
  createManualClock,
  type ManualClock,
  requireDockerOrSkip,
  type StartedPostgres,
  startPostgresContainer,
  truncateDomainTablesStatement,
} from '@qauth-labs/shared-testing';
import Fastify from 'fastify';
import { Registry } from 'prom-client';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

import { eventDeliveryPlugin } from './fastify-plugin-event-delivery';

const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
const KIND = 'test';
const T0 = 1_800_000_000_000;
const LEASE = 60_000;

function signedIn(realm: string): EmitEvent<'urn:qauth:event:user.signed_in:v1-rc.0'> {
  const userId = randomUUID();
  return {
    type: SIGNED_IN,
    realm,
    actor: { type: 'user', id: userId },
    subject: { type: 'user', id: userId },
    data: { method: 'password' },
  };
}

const signer: DeliverySigner = {
  signWebhook: async () => 'v1,c2lnbmF0dXJl',
  signEventToken: async () => 'h.p.s',
  decrypt: async () => new Uint8Array(),
};

const silent = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
};

/** What the receiver got: one entry per request. */
interface Received {
  readonly destination: string;
  readonly webhookId: string;
  readonly eventId: string;
  readonly at: number;
}

/** How the receiver answers one destination's requests. */
type Answer = 'ok' | 'unavailable' | 'hang';

/** A test receiver over HTTP: it records every request, then answers as told. */
interface Receiver {
  readonly url: string;
  readonly received: Received[];
  answer: (destination: string, call: number) => Answer;
  close(): Promise<void>;
}

async function startReceiver(): Promise<Receiver> {
  const received: Received[] = [];
  const counts = new Map<string, number>();
  const receiver: Receiver = {
    url: '',
    received,
    answer: () => 'ok',
    close: async () => undefined,
  };
  const server: Server = createServer((request: IncomingMessage, response: ServerResponse) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      const destination = (request.url ?? '/').slice(1);
      const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { id: string };
      received.push({
        destination,
        webhookId: String(request.headers['webhook-id']),
        eventId: body.id,
        at: Date.now(),
      });
      const call = (counts.get(destination) ?? 0) + 1;
      counts.set(destination, call);
      const answer = receiver.answer(destination, call);
      if (answer === 'hang') return;
      response.writeHead(answer === 'ok' ? 204 : 503).end();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return Object.assign(receiver, {
    url: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  });
}

/**
 * A route of kind `test` that POSTs the event to the receiver, the event id
 * in `webhook-id`, as the webhook route will. `after` runs once the receiver
 * answered, before the outcome goes back to the role.
 */
function httpRoute(
  receiver: Receiver,
  destinations: readonly RouteDestination[],
  after: () => Promise<void> = async () => undefined
): DeliveryRoute {
  return {
    kind: KIND,
    destinations: async () => destinations,
    async deliver(delivery, event, { signal }) {
      const response = await fetch(`${receiver.url}/${delivery.destinationId}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'webhook-id': event.id },
        body: JSON.stringify(event),
        signal,
      });
      await after();
      return response.ok
        ? { ok: true, statusCode: response.status }
        : { ok: false, statusCode: response.status, errorClass: 'http_status' };
    },
  };
}

describe('the delivery role on a real Postgres', () => {
  let postgres: StartedPostgres | undefined;
  let admin: DatabaseInstance | undefined;
  let dockerUp = false;
  let receiver: Receiver;
  const cleanups: Array<() => Promise<void>> = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    postgres = await startPostgresContainer({ schema: 'migrated' });
    admin = createDatabase({ connectionString: postgres.connectionString });
  }, 240_000);

  afterAll(async () => {
    await admin?.close();
    await postgres?.stop();
  });

  beforeEach(async (ctx) => {
    if (!dockerUp) {
      ctx.skip();
      return;
    }
    await database().pool.query(truncateDomainTablesStatement());
    receiver = await startReceiver();
  });

  afterEach(async () => {
    for (const cleanup of cleanups.splice(0).reverse()) await cleanup();
    await receiver?.close();
  });

  function database(): DatabaseInstance {
    if (!admin) throw new Error('database not started');
    return admin;
  }

  const events = () => createEventsRepository(database().db);
  const queue = () => createEventDeliveriesRepository(database().db);

  /** A worker: its own pool, its own role. */
  function startWorker(
    routes: DeliveryRoute[],
    settings: DeliverySettingsInput,
    clock?: ManualClock,
    random?: () => number
  ): { role: DeliveryRole; db: DatabaseInstance } {
    if (!postgres) throw new Error('database not started');
    const db = createDatabase({
      connectionString: postgres.connectionString,
      pool: { max: 5, min: 0 },
    });
    const role = startDeliveryRole({
      store: createEventDeliveriesRepository(db.db),
      routes,
      signer,
      log: silent,
      settings,
      ...(clock ? { clock } : {}),
      ...(random ? { random } : {}),
    });
    return { role, db };
  }

  /** Wait until the fan-out has given the realm its position, as a running role does first. */
  async function positioned(realm: string): Promise<void> {
    await vi.waitFor(
      async () => {
        const { rows } = await database().pool.query(
          'SELECT 1 FROM event_delivery_positions WHERE realm_id = $1',
          [realm]
        );
        expect(rows).toHaveLength(1);
      },
      { timeout: 10_000, interval: 20 }
    );
  }

  async function deliveryRows(): Promise<
    Array<{ destination_id: string; event_id: string; status: string; attempt_count: number }>
  > {
    const { rows } = await database().pool.query(
      `SELECT destination_id, event_id::text, status, attempt_count
         FROM event_deliveries ORDER BY destination_id, event_xid, event_seq`
    );
    return rows;
  }

  /** Move a manual clock in steps, letting real database work run between them, until `done`. */
  async function advanceUntil(
    clock: ManualClock,
    stepMs: number,
    done: () => Promise<boolean>,
    maxSteps = 1_000
  ): Promise<void> {
    for (let step = 0; step < maxSteps; step += 1) {
      if (await done()) return;
      await clock.advanceBy(stepMs);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
    throw new Error(`not done after ${maxSteps} steps of ${stepMs} ms`);
  }

  it('delivers an event again, with the same id, after the worker that claimed it died', async () => {
    const realm = randomUUID();
    const destinations = [{ id: 'receiver', realmId: realm }];
    const settings = { leaseMs: LEASE, attemptTimeoutMs: 30_000, pollIntervalMs: 1_000 };

    // Worker A posts the event, and dies before it records the success: its
    // route never returns, its clock never moves again, its pool is closed.
    const clockA = createManualClock(T0);
    const a = startWorker(
      [httpRoute(receiver, destinations, () => new Promise<void>(() => undefined))],
      settings,
      clockA
    );
    await clockA.advanceBy(0);
    await positioned(realm);
    const eventId = await events().emitInOwnTransaction(signedIn(realm));
    await clockA.advanceBy(1_000);
    await vi.waitFor(() => expect(receiver.received).toHaveLength(1), { timeout: 10_000 });
    await a.db.close();
    expect(await deliveryRows()).toEqual([
      { destination_id: 'receiver', event_id: eventId, status: 'pending', attempt_count: 1 },
    ]);

    // Worker B: the row comes due when A's lease runs out.
    const clockB = createManualClock(T0 + 1_000);
    const b = startWorker([httpRoute(receiver, destinations)], settings, clockB);
    cleanups.push(async () => {
      await b.role.stop();
      await b.db.close();
    });
    await clockB.advanceBy(0);
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(receiver.received).toHaveLength(1);

    await advanceUntil(clockB, 1_000, async () => (await deliveryRows())[0].status === 'delivered');
    expect(clockB.now()).toBeGreaterThanOrEqual(T0 + 1_000 + LEASE);
    expect(receiver.received.map(({ webhookId, eventId: id }) => [webhookId, id])).toEqual([
      [eventId, eventId],
      [eventId, eventId],
    ]);
    expect(await deliveryRows()).toEqual([
      { destination_id: 'receiver', event_id: eventId, status: 'delivered', attempt_count: 2 },
    ]);
  });

  it('two workers on one database deliver each event to each destination once', async () => {
    const realm = randomUUID();
    const destinations = ['d1', 'd2', 'd3'].map((id) => ({ id, realmId: realm }));
    const settings = { pollIntervalMs: 20, concurrency: 3, maxInFlightPerDestination: 2 };
    for (const route of [httpRoute(receiver, destinations), httpRoute(receiver, destinations)]) {
      const worker = startWorker([route], settings);
      cleanups.push(async () => {
        await worker.role.stop();
        await worker.db.close();
      });
    }
    await positioned(realm);

    const ids: string[] = [];
    for (let i = 0; i < 10; i += 1) ids.push(await events().emitInOwnTransaction(signedIn(realm)));
    // Some events committed together, in one transaction.
    await database().db.transaction(async (tx) => {
      for (let i = 0; i < 20; i += 1) ids.push(await events().emit(tx, signedIn(realm)));
    });

    await vi.waitFor(
      async () => {
        const rows = await deliveryRows();
        expect(rows).toHaveLength(90);
        expect(rows.every((row) => row.status === 'delivered')).toBe(true);
      },
      { timeout: 30_000, interval: 50 }
    );
    const byPair = new Map<string, number>();
    for (const { destination, eventId } of receiver.received) {
      byPair.set(`${destination}/${eventId}`, (byPair.get(`${destination}/${eventId}`) ?? 0) + 1);
    }
    expect(byPair.size).toBe(90);
    for (const destination of ['d1', 'd2', 'd3']) {
      for (const id of ids)
        expect(byPair.get(`${destination}/${id}`), `${destination}/${id}`).toBe(1);
    }
    expect((await deliveryRows()).every((row) => row.attempt_count === 1)).toBe(true);
  });

  it('on a fake clock, retries with growing delays to delivered, and ends failed after the last attempt', async () => {
    const realm = randomUUID();
    const destinations = [
      { id: 'flaky', realmId: realm },
      { id: 'down', realmId: realm },
    ];
    receiver.answer = (destination, call) =>
      destination === 'flaky' && call > 3 ? 'ok' : 'unavailable';
    const clock = createManualClock(T0);
    const attempts: Array<{ destination: string; at: number }> = [];
    const route = httpRoute(receiver, destinations);
    const recording: DeliveryRoute = {
      ...route,
      deliver: (delivery, event, context) => {
        attempts.push({ destination: delivery.destinationId, at: clock.now() });
        return route.deliver(delivery, event, context);
      },
    };
    const worker = startWorker(
      [recording],
      {
        maxAttempts: 5,
        pollIntervalMs: 100,
        retry: { initialDelayMs: 1_000, maxDelayMs: 60_000, multiplier: 2, jitter: 0.2 },
      },
      clock,
      // Takes off half the jitter share: waits of 900, 1800, 3600, 7200 ms.
      () => 0.5
    );
    cleanups.push(async () => {
      const stopped = worker.role.stop();
      await clock.advanceBy(10_000);
      await stopped;
      await worker.db.close();
    });
    await clock.advanceBy(0);
    await positioned(realm);
    const eventId = await events().emitInOwnTransaction(signedIn(realm));

    await advanceUntil(clock, 100, async () => {
      const rows = await deliveryRows();
      return rows.length === 2 && rows.every((row) => row.status !== 'pending');
    });

    const times = (destination: string) =>
      attempts
        .filter((attempt) => attempt.destination === destination)
        .map((attempt) => attempt.at);
    const gaps = (at: number[]) => at.slice(1).map((time, i) => time - at[i]);
    const flaky = gaps(times('flaky'));
    expect(flaky).toHaveLength(3);
    expect(flaky[0]).toBeGreaterThanOrEqual(900);
    expect(flaky[1]).toBeGreaterThan(flaky[0]);
    expect(flaky[2]).toBeGreaterThan(flaky[1]);
    const down = gaps(times('down'));
    expect(down).toHaveLength(4);
    for (let i = 1; i < down.length; i += 1) expect(down[i]).toBeGreaterThan(down[i - 1]);

    const rows = await queue().listForEvent(eventId);
    expect(rows.map((row) => [row.destinationId, row.status, row.attemptCount])).toEqual(
      expect.arrayContaining([
        ['flaky', 'delivered', 4],
        ['down', 'failed', 5],
      ])
    );
    expect(rows.find((row) => row.destinationId === 'down')).toMatchObject({
      lastStatusCode: 503,
      lastErrorClass: 'http_status',
      lockedUntil: null,
    });
    expect(rows.find((row) => row.destinationId === 'flaky')).toMatchObject({
      lastStatusCode: 204,
      lastErrorClass: null,
    });
  });

  it('with one destination down, another receives every event without waiting for it', async () => {
    const realm = randomUUID();
    const destinations = [
      { id: 'down', realmId: realm },
      { id: 'up', realmId: realm },
    ];
    // The down destination takes the request and never answers.
    receiver.answer = (destination) => (destination === 'down' ? 'hang' : 'ok');
    const worker = startWorker([httpRoute(receiver, destinations)], {
      pollIntervalMs: 50,
      concurrency: 4,
      maxInFlightPerDestination: 2,
      attemptTimeoutMs: 15_000,
      leaseMs: 30_000,
      shutdownTimeoutMs: 200,
    });
    cleanups.push(async () => {
      await worker.role.stop();
      await worker.db.close();
    });
    await positioned(realm);

    const started = Date.now();
    for (let i = 0; i < 20; i += 1) await events().emitInOwnTransaction(signedIn(realm));
    await vi.waitFor(
      () =>
        expect(receiver.received.filter((request) => request.destination === 'up')).toHaveLength(
          20
        ),
      { timeout: 10_000, interval: 20 }
    );
    // Every one of them while the down destination's first attempts still hang.
    expect(Date.now() - started).toBeLessThan(15_000);
    const { rows } = await database().pool.query(
      `SELECT status, count(*)::int AS n, max(attempt_count) AS attempts, max(last_error_class) AS error
         FROM event_deliveries WHERE destination_id = 'down' GROUP BY status`
    );
    expect(rows).toEqual([{ status: 'pending', n: 20, attempts: 1, error: null }]);
    expect(receiver.received.filter((request) => request.destination === 'down')).toHaveLength(2);
  });

  describe('the plugin', () => {
    it('runs the role from ready to close, and its pending count and lag grow while a route fails', async () => {
      const realm = randomUUID();
      receiver.answer = () => 'unavailable';
      const registry = new Registry();
      const app = Fastify({ logger: false });
      const fakeSigner = {
        signWebhook: vi.fn(async () => 'v1,x'),
        signJws: vi.fn(async () => 'h.p.s'),
      } as unknown as Signer;
      await app.register(eventDeliveryPlugin, {
        db: database().db,
        signer: fakeSigner,
        routes: [httpRoute(receiver, [{ id: 'failing', realmId: realm }])],
        registry,
        settings: { pollIntervalMs: 50 },
      });
      await app.ready();
      cleanups.push(() => app.close());
      await positioned(realm);

      const value = async (pattern: RegExp): Promise<number> => {
        const match = pattern.exec(await registry.metrics());
        return match ? Number(match[1]) : Number.NaN;
      };
      const pending = () => value(/^qauth_events_pending\{kind="test"\} (\S+)$/m);
      const lag = () => value(/^qauth_events_delivery_lag_seconds (\S+)$/m);
      const retries = () =>
        value(/^qauth_events_delivery_attempts_total\{kind="test",result="retry"\} (\S+)$/m);
      expect(await pending()).toBe(0);
      expect(await lag()).toBe(0);

      for (let i = 0; i < 2; i += 1) await events().emitInOwnTransaction(signedIn(realm));
      await vi.waitFor(async () => expect(await retries()).toBe(2), { timeout: 10_000 });
      expect(await pending()).toBe(2);
      const firstLag = await lag();
      expect(firstLag).toBeGreaterThan(0);

      for (let i = 0; i < 3; i += 1) await events().emitInOwnTransaction(signedIn(realm));
      await vi.waitFor(async () => expect(await retries()).toBe(5), { timeout: 10_000 });
      expect(await pending()).toBe(5);
      expect(await lag()).toBeGreaterThan(firstLag);
    });
  });
});
