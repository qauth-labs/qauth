import { randomUUID } from 'node:crypto';

import { EventValidationError, parseEvent } from '@qauth-labs/shared-events';
import { stepUrn } from '@qauth-labs/shared-interaction-contract';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';
import { describe, expect, it, vi } from 'vitest';

import { createMemoryInteractionRedis } from '../../testing/interaction-redis';
import { CHECKED_EVENT_ID } from '../../testing/user-events';
import { REDIS_KEYS } from '../constants';
import {
  claimExpiredInteraction,
  deleteInteraction,
  expiredInteractionEntries,
  insertInteraction,
  interactionIdHash,
  type InteractionRecord,
  mintInteractionId,
} from '../helpers/interaction-record';
import {
  createInteractionExpiryJob,
  INTERACTION_EXPIRY_BATCH,
  INTERACTION_EXPIRY_INTERVAL_MS,
  INTERACTION_EXPIRY_JOB_NAME,
} from './interaction-expiry';

/**
 * THE INTERACTION EXPIRY SWEEP (#592): every interaction that reaches its
 * absolute expiry unfinished is audited once, with the step it ended at, and
 * cleared from Redis. The rules that refuse it at expiry are in
 * `helpers/interaction.test.ts`; this pins the sweep.
 */

const REALM_ID = '22222222-2222-4222-8222-222222222222';
const USER_ID = '11111111-1111-4111-8111-111111111111';
const NOW = Date.now();

function record(overrides: Partial<InteractionRecord> = {}): InteractionRecord {
  return {
    v: 1,
    ref: randomUUID(),
    realmId: REALM_ID,
    purpose: 'authorization',
    request: {
      response_type: 'code',
      client_id: 'notes-app',
      redirect_uri: 'https://notes.example.com/callback',
      code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',
      code_challenge_method: 'S256',
      resource: undefined,
    },
    step: { name: stepUrn('password'), params: {}, alternatives: [] },
    personal: {},
    transaction: { amr: [] },
    flowBinding: 'A'.repeat(43),
    revision: 0,
    createdAt: NOW - 1_800_000,
    expiresAt: NOW,
    ...overrides,
  };
}

/**
 * `redis` as a client whose connection drops at round trip `at` (1-based):
 * that command, or that whole `MULTI`, never reaches the server, as when the
 * connection closes before it is written.
 */
function droppingAt<Client extends object>(redis: Client, at: number): Client {
  let trips = 0;
  const trip = () => {
    trips += 1;
    if (trips === at) throw new Error('Connection is closed.');
  };
  const client: Client = new Proxy(redis, {
    get(target, name) {
      const value = Reflect.get(target, name) as unknown;
      if (typeof value !== 'function') return value;
      if (name === 'multi') {
        return () => {
          const block = (value as () => Record<string, (...args: unknown[]) => unknown>).call(
            target
          );
          const queued: Record<string, unknown> = new Proxy(block, {
            get(_block, command) {
              if (command === 'exec') {
                return async () => {
                  trip();
                  return block['exec']();
                };
              }
              return (...args: unknown[]) => {
                block[String(command)](...args);
                return queued;
              };
            },
          });
          return queued;
        };
      }
      return async (...args: unknown[]) => {
        trip();
        return (value as (...args: unknown[]) => Promise<unknown>).apply(target, args);
      };
    },
  });
  return client;
}

/** The sweep's world: an in-memory Redis and an event store that checks each event. */
function world() {
  const redis = createMemoryInteractionRedis();
  const emitted: Record<string, unknown>[] = [];
  const events = {
    emitInOwnTransaction: vi.fn(async (event: Record<string, unknown>) => {
      // The store refuses an event the contract refuses: so does this one.
      parseEvent({
        id: CHECKED_EVENT_ID,
        time: new Date(NOW).toISOString(),
        category: 'user',
        ...event,
      });
      emitted.push(event);
      return CHECKED_EVENT_ID;
    }),
  };
  const job = createInteractionExpiryJob({
    redis: redis as unknown as FastifyInstance['redis'],
    events: events as unknown as FastifyInstance['repositories']['events'],
  });
  return { redis, events, emitted, job };
}

function context(now = NOW + 1) {
  const log = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
  return {
    signal: new AbortController().signal,
    now: () => now,
    log: log as unknown as FastifyBaseLogger,
  };
}

async function insert(redis: ReturnType<typeof world>['redis'], value: InteractionRecord) {
  const id = mintInteractionId();
  await insertInteraction(
    redis as unknown as FastifyInstance['redis'],
    interactionIdHash(id),
    value
  );
  return { id, idHash: interactionIdHash(id) };
}

describe('interaction-expiry (#592)', () => {
  it('runs every minute on the web role', () => {
    const { job } = world();
    expect(job.name).toBe(INTERACTION_EXPIRY_JOB_NAME);
    expect(job.role).toBe('web');
    expect(job.intervalMs).toBe(INTERACTION_EXPIRY_INTERVAL_MS);
  });

  it('audits each expired interaction once, with its step, client and user, and clears it', async () => {
    const { redis, emitted, job } = world();
    const signedIn = record({ transaction: { userId: USER_ID, amr: ['pwd'] } });
    const anonymous = record({ expiresAt: NOW - 5_000 });
    const live = record({ expiresAt: NOW + 60_000 });
    for (const value of [signedIn, anonymous, live]) await insert(redis, value);

    // Redis keeps an expired record a grace longer; set the clock inside it.
    vi.useFakeTimers({ toFake: ['Date'], now: NOW + 1 });
    try {
      await job.run(context());
      await job.run(context());
    } finally {
      vi.useRealTimers();
    }

    expect(emitted).toHaveLength(2);
    expect(emitted).toContainEqual({
      type: 'urn:qauth:event:interaction.expired:v1-rc.0',
      realm: REALM_ID,
      actor: { type: 'system' },
      subject: { type: 'user', id: USER_ID },
      client: { id: 'notes-app' },
      data: { interaction: signedIn.ref, step: stepUrn('password') },
    });
    expect(emitted).toContainEqual({
      type: 'urn:qauth:event:interaction.expired:v1-rc.0',
      realm: REALM_ID,
      actor: { type: 'system' },
      client: { id: 'notes-app' },
      data: { interaction: anonymous.ref, step: stepUrn('password') },
    });
    // Only the live one is left: its record, its turn and its index member.
    expect(redis.strings.size).toBe(2);
    expect([
      ...(redis.sortedSets.get(REDIS_KEYS.INTERACTION_EXPIRY_INDEX())?.keys() ?? []),
    ]).toEqual([expect.stringContaining(live.ref)]);
  });

  it('reports nothing for an interaction that finished or was cancelled', async () => {
    const { redis, emitted, job } = world();
    const done = record();
    const { idHash } = await insert(redis, done);
    await deleteInteraction(redis as unknown as FastifyInstance['redis'], done, idHash);

    await job.run(context());

    expect(emitted).toHaveLength(0);
  });

  it('reports an expired interaction whose record is gone, without a step', async () => {
    const { redis, emitted, job } = world();
    const value = record();
    const { idHash } = await insert(redis, value);
    redis.strings.delete(REDIS_KEYS.INTERACTION(REALM_ID, idHash));

    await job.run(context());

    expect(emitted).toEqual([
      {
        type: 'urn:qauth:event:interaction.expired:v1-rc.0',
        realm: REALM_ID,
        actor: { type: 'system' },
        data: { interaction: value.ref },
      },
    ]);
  });

  it('puts an interaction back when its event cannot be written, and reports it on the next run', async () => {
    const { redis, events, emitted, job } = world();
    const value = record();
    await insert(redis, value);
    events.emitInOwnTransaction.mockRejectedValueOnce(new Error('event store down'));

    vi.useFakeTimers({ toFake: ['Date'], now: NOW + 1 });
    try {
      await expect(job.run(context())).rejects.toThrow('event store down');
      expect(emitted).toHaveLength(0);
      await job.run(context());
    } finally {
      vi.useRealTimers();
    }

    expect(emitted).toHaveLength(1);
    expect(emitted[0]).toMatchObject({
      data: { interaction: value.ref, step: stepUrn('password') },
    });
  });

  it('claims an expired interaction whole: its index member, its turn and its record', async () => {
    const { redis } = world();
    const value = record();
    const { idHash } = await insert(redis, value);
    const client = redis as unknown as FastifyInstance['redis'];
    const log = context().log;

    vi.useFakeTimers({ toFake: ['Date'], now: NOW + 1 });
    try {
      const [entry] = await expiredInteractionEntries(client, NOW + 1, 10);
      const claimed = await claimExpiredInteraction(client, log, entry);
      // A second claim of the same entry, as a second sweep would make it.
      const again = await claimExpiredInteraction(client, log, entry);

      expect(claimed).toMatchObject({
        realmId: REALM_ID,
        ref: value.ref,
        idHash,
        record: { ref: value.ref, step: value.step, revision: 0 },
      });
      expect(again).toBeNull();
    } finally {
      vi.useRealTimers();
    }
    expect(redis.strings.size).toBe(0);
    expect(redis.sortedSets.size).toBe(0);
  });

  it('never loses an expiry to a connection that drops in the middle of a run', async () => {
    // Round trips of one run: the index read, the claim, then the next index
    // read. Wherever the connection drops, the next run reports the expiry,
    // with its step, exactly once.
    for (let at = 1; at <= 3; at += 1) {
      const { redis, events, emitted } = world();
      const value = record();
      await insert(redis, value);
      const flaky = createInteractionExpiryJob({
        redis: droppingAt(redis, at) as unknown as FastifyInstance['redis'],
        events: events as unknown as FastifyInstance['repositories']['events'],
      });
      const healthy = createInteractionExpiryJob({
        redis: redis as unknown as FastifyInstance['redis'],
        events: events as unknown as FastifyInstance['repositories']['events'],
      });

      vi.useFakeTimers({ toFake: ['Date'], now: NOW + 1 });
      try {
        await flaky.run(context()).catch(() => undefined);
        await healthy.run(context());
        await healthy.run(context());
      } finally {
        vi.useRealTimers();
      }

      expect(emitted, `dropped at round trip ${at}`).toEqual([
        expect.objectContaining({ data: { interaction: value.ref, step: stepUrn('password') } }),
      ]);
      expect(redis.sortedSets.size, `dropped at round trip ${at}`).toBe(0);
    }
  });

  it('logs an expiry by reference when neither its event nor its relist can be written', async () => {
    const { redis, events } = world();
    const value = record();
    await insert(redis, value);
    events.emitInOwnTransaction.mockRejectedValueOnce(new Error('event store down'));
    // The claim is the second round trip, the relist the third.
    const job = createInteractionExpiryJob({
      redis: droppingAt(redis, 3) as unknown as FastifyInstance['redis'],
      events: events as unknown as FastifyInstance['repositories']['events'],
    });
    const ctx = context();

    vi.useFakeTimers({ toFake: ['Date'], now: NOW + 1 });
    try {
      await expect(job.run(ctx)).rejects.toThrow('event store down');
    } finally {
      vi.useRealTimers();
    }

    expect(ctx.log.error).toHaveBeenCalledWith(
      expect.objectContaining({ interaction: value.ref, err: expect.any(Error) }),
      'interaction expiry could not be audited or listed again; lost'
    );
  });

  it('works through more expired interactions than one batch', async () => {
    const { redis, emitted, job } = world();
    for (let index = 0; index < INTERACTION_EXPIRY_BATCH + 3; index += 1) {
      await insert(redis, record({ expiresAt: NOW - index }));
    }

    await job.run(context());

    expect(emitted).toHaveLength(INTERACTION_EXPIRY_BATCH + 3);
    expect(redis.sortedSets.size).toBe(0);
  });

  it('drops an event the contract refuses, and goes on with the rest', async () => {
    const { redis, events, emitted, job } = world();
    const refused = record({ expiresAt: NOW - 10 });
    const fine = record({ expiresAt: NOW - 5 });
    await insert(redis, refused);
    await insert(redis, fine);
    events.emitInOwnTransaction.mockImplementationOnce(async () => {
      throw new EventValidationError('not an event', ['/data/step: Invalid']);
    });
    const ctx = context();

    await job.run(ctx);
    await job.run(ctx);

    expect(emitted).toEqual([
      expect.objectContaining({ data: expect.objectContaining({ interaction: fine.ref }) }),
    ]);
    expect(ctx.log.warn).toHaveBeenCalledWith(
      expect.objectContaining({ interaction: refused.ref }),
      'interaction expiry event refused by the event contract; dropped'
    );
    expect(redis.sortedSets.size).toBe(0);
  });

  it('names no client when the client_id is longer than an event holds', async () => {
    const { redis, emitted, job } = world();
    const value = record();
    value.request.client_id = `https://client.example.com/${'c'.repeat(300)}`;
    await insert(redis, value);

    await job.run(context());

    expect(emitted).toHaveLength(1);
    expect(emitted[0]).not.toHaveProperty('client');
  });
});
