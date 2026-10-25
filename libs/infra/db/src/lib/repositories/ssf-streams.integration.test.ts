/**
 * Real-Postgres integration tests for the Shared Signals Framework streams
 * (issue #410).
 *
 * What only a database can prove: a receiver has one stream per realm and
 * reaches only its own; the subject cap holds under concurrent adds; the
 * delivery route lists only streams it may deliver to (realm switch on,
 * receiver active, not disabled); a verification event's delivery row is
 * written only for the event its own transaction wrote and only for a stream
 * of that event's realm; the status reads the latest failed attempt; the
 * fan-out's subject filter gives a stream only events about its subjects; and
 * a role holding only the delivery grants can read what the route reads.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type {
  Database,
  EmitEvent,
  EventDeliveriesRepository,
  EventsRepository,
  NewSsfStream,
  SsfStreamsRepository,
} from '../../types';
import { eventDeliveryGrantStatements } from '../events/delivery-grants';
import { createEventDeliveriesRepository } from './event-deliveries.repository';
import { createEventsRepository } from './events.repository';
import { type IntegrationDb, setupIntegrationDb } from './integration-setup';
import { createSsfStreamsRepository, SSF_DELIVERY_KIND } from './ssf-streams.repository';

const VERIFICATION = 'urn:qauth:event:ssf.stream.verification_requested:v1-rc.0';
const SIGNED_OUT = 'urn:qauth:event:user.signed_out:v1-rc.0';
const NOW = 1_800_000_000_000;
const PUSH = 'urn:ietf:rfc:8935';

describe('SSF streams integration (real Postgres)', () => {
  let ctx: IntegrationDb | undefined;
  let dockerUp = false;
  let streams: SsfStreamsRepository;
  let store: EventsRepository;
  let queue: EventDeliveriesRepository;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    ctx = await setupIntegrationDb();
    streams = createSsfStreamsRepository(ctx.database.db);
    store = createEventsRepository(ctx.database.db);
    queue = createEventDeliveriesRepository(ctx.database.db);
  }, 180_000);

  afterAll(async () => {
    await ctx?.teardown();
  });

  beforeEach(async (testCtx) => {
    if (!dockerUp || !ctx) {
      testCtx.skip();
      return;
    }
    await ctx.reset();
  });

  function pool(): Pool {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.pool;
  }

  function db(): Database {
    if (!ctx) throw new Error('no ctx');
    return ctx.database.db;
  }

  async function realm(options: { ssf?: boolean } = {}): Promise<string> {
    const { rows } = await pool().query<{ id: string }>(
      `INSERT INTO realms (name, ssf_transmitter_enabled) VALUES ($1, $2) RETURNING id`,
      [`realm-${randomUUID()}`, options.ssf ?? true]
    );
    return rows[0].id;
  }

  async function client(realmId: string): Promise<{ id: string; clientId: string }> {
    const clientId = `receiver-${randomUUID()}`;
    const { rows } = await pool().query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris, scopes)
       VALUES ($1, $2, 'x', 'receiver', '[]', '["ssf:stream"]') RETURNING id`,
      [realmId, clientId]
    );
    return { id: rows[0].id, clientId };
  }

  function newStream(realmId: string, receiverClientId: string): NewSsfStream {
    return {
      realmId,
      receiverClientId,
      audience: 'receiver',
      eventsRequested: [],
      deliveryMethod: PUSH,
      endpointUrl: 'https://receiver.example/events',
      authorizationHeader: null,
      description: null,
    };
  }

  async function streamOf(options: { ssf?: boolean } = {}) {
    const realmId = await realm(options);
    const receiver = await client(realmId);
    const stream = await streams.create(newStream(realmId, receiver.id));
    if (!stream) throw new Error('no stream');
    return {
      realmId,
      receiver,
      stream,
      key: { realmId, receiverClientId: receiver.id, streamId: stream.id },
    };
  }

  /** Emit a verification event for a stream and enqueue its row, in one transaction. */
  async function verify(realmId: string, streamId: string, enqueueFor = streamId) {
    return db().transaction(async (tx) => {
      const eventId = await store.emit(tx, {
        type: VERIFICATION,
        realm: realmId,
        subject: { type: 'ssf_stream', id: streamId },
        data: { state: 'abc' },
      });
      const enqueued = await streams.enqueueForEvent(tx, {
        streamId: enqueueFor,
        eventId,
        now: NOW,
      });
      return { eventId, enqueued };
    });
  }

  it('keeps one stream per receiver and realm, reachable only by that receiver', async () => {
    const { realmId, receiver, stream, key } = await streamOf();
    expect(stream).toMatchObject({ status: 'enabled', deliveryMethod: PUSH, eventsRequested: [] });
    expect(await streams.create(newStream(realmId, receiver.id))).toBeNull();

    const other = await client(realmId);
    expect(await streams.find({ ...key, receiverClientId: other.id })).toBeUndefined();
    expect(await streams.list(realmId, other.id)).toEqual([]);
    expect(
      await streams.update({ ...key, receiverClientId: other.id }, { description: 'x' }, NOW)
    ).toBeUndefined();
    expect(await streams.remove({ ...key, receiverClientId: other.id })).toBe(false);
    expect(await streams.find({ ...key, streamId: 'not-a-uuid' })).toBeUndefined();

    const updated = await streams.update(
      key,
      { eventsRequested: ['https://example/a'], description: 'mine' },
      NOW
    );
    expect(updated).toMatchObject({ eventsRequested: ['https://example/a'], description: 'mine' });
    expect(await streams.setStatus(key, 'paused', 'maintenance', NOW)).toMatchObject({
      status: 'paused',
      statusReason: 'maintenance',
    });
    expect(await streams.list(realmId, receiver.id)).toHaveLength(1);
    expect(await streams.remove(key)).toBe(true);
    expect(await streams.find(key)).toBeUndefined();
  });

  it('adds a subject once and refuses a new one past the cap, also under concurrent adds', async () => {
    const { stream } = await streamOf();
    const subject = (n: number) => ({
      subjectKey: `{"format":"opaque","id":"${n}"}`,
      subject: { format: 'opaque', id: String(n) },
      eventSubject: { type: 'client', id: String(n) },
      verified: true,
    });
    expect(await streams.addSubject(stream.id, subject(1), 3)).toBe('added');
    expect(await streams.addSubject(stream.id, subject(1), 3)).toBe('present');

    const results = await Promise.all(
      [2, 3, 4, 5, 6].map((n) => streams.addSubject(stream.id, subject(n), 3))
    );
    expect(results.filter((result) => result === 'added')).toHaveLength(2);
    expect(results.filter((result) => result === 'full')).toHaveLength(3);
    expect(await streams.listSubjects(stream.id)).toHaveLength(3);
    // A subject already there is still present at the cap.
    expect(await streams.addSubject(stream.id, subject(1), 3)).toBe('present');

    expect(await streams.removeSubject(stream.id, subject(1).subjectKey)).toBe(true);
    expect(await streams.removeSubject(stream.id, subject(1).subjectKey)).toBe(false);
  });

  it('lists only the streams the route may deliver to, with their placed subjects', async () => {
    const enabled = await streamOf();
    const paused = await streamOf();
    await streams.setStatus(paused.key, 'paused', null, NOW);
    const disabled = await streamOf();
    await streams.setStatus(disabled.key, 'disabled', null, NOW);
    const realmOff = await streamOf({ ssf: false });
    const suspended = await streamOf();
    await pool().query(`UPDATE oauth_clients SET suspended = true WHERE id = $1`, [
      suspended.receiver.id,
    ]);
    const clientOff = await streamOf();
    await pool().query(`UPDATE oauth_clients SET enabled = false WHERE id = $1`, [
      clientOff.receiver.id,
    ]);
    const scopeGone = await streamOf();
    await pool().query(`UPDATE oauth_clients SET scopes = '["reports:read"]' WHERE id = $1`, [
      scopeGone.receiver.id,
    ]);

    await streams.addSubject(
      enabled.stream.id,
      {
        subjectKey: 'user',
        subject: { format: 'iss_sub' },
        eventSubject: { type: 'user', id: 'u1' },
        verified: true,
      },
      10
    );
    await streams.addSubject(
      enabled.stream.id,
      { subjectKey: 'email', subject: { format: 'email' }, eventSubject: null, verified: false },
      10
    );

    const listed = await streams.listDestinations();
    expect(listed.map((destination) => destination.id).sort()).toEqual(
      [enabled.stream.id, paused.stream.id].sort()
    );
    expect(listed.find((destination) => destination.id === enabled.stream.id)).toEqual({
      id: enabled.stream.id,
      realmId: enabled.realmId,
      status: 'enabled',
      eventsRequested: [],
      subjects: [{ type: 'user', id: 'u1' }],
    });
    expect(listed.find((destination) => destination.id === paused.stream.id)?.subjects).toEqual([]);

    expect(await streams.findForDelivery(enabled.stream.id)).toMatchObject({ active: true });
    expect(await streams.findForDelivery(realmOff.stream.id)).toMatchObject({ active: false });
    expect(await streams.findForDelivery(suspended.stream.id)).toMatchObject({ active: false });
    expect(await streams.findForDelivery(clientOff.stream.id)).toMatchObject({ active: false });
    expect(await streams.findForDelivery(scopeGone.stream.id)).toMatchObject({ active: false });
    expect(await streams.findForDelivery(randomUUID())).toBeUndefined();
  });

  it("writes a verification delivery for its own transaction's event and its own realm only", async () => {
    const { realmId, stream } = await streamOf();
    const { eventId, enqueued } = await verify(realmId, stream.id);
    expect(enqueued).toBe(true);
    const rows = await queue.listForEvent(eventId);
    expect(rows).toMatchObject([
      { destinationKind: SSF_DELIVERY_KIND, destinationId: stream.id, status: 'pending' },
    ]);
    expect(await queue.dueDestinations([SSF_DELIVERY_KIND], NOW)).toEqual([
      { kind: SSF_DELIVERY_KIND, id: stream.id },
    ]);

    // An event another transaction wrote is not this transaction's to address.
    const enqueuedLater = await db().transaction((tx) =>
      streams.enqueueForEvent(tx, { streamId: stream.id, eventId, now: NOW })
    );
    expect(enqueuedLater).toBe(false);

    // A stream of another realm never gets this realm's event.
    const other = await streamOf();
    const crossed = await verify(realmId, stream.id, other.stream.id);
    expect(crossed.enqueued).toBe(false);
    expect(await queue.listForEvent(crossed.eventId)).toEqual([]);
  });

  it('reports the pending deliveries and the latest failed attempt', async () => {
    const { realmId, stream } = await streamOf();
    expect(await streams.deliveryStatus(stream.id)).toEqual({ pending: 0 });
    const { eventId } = await verify(realmId, stream.id);
    expect(await streams.deliveryStatus(stream.id)).toEqual({ pending: 1 });

    const pick = {
      picks: [{ kind: SSF_DELIVERY_KIND, id: stream.id, limit: 1 }],
      leaseMs: 60_000,
      maxAttempts: 2,
    };
    const [first] = await queue.claim({ ...pick, now: NOW });
    await queue.record(
      first,
      { result: 'retry', nextAttemptAt: NOW + 30_000, statusCode: 503, errorClass: 'http_status' },
      NOW + 1
    );
    expect(await streams.deliveryStatus(stream.id)).toEqual({
      pending: 1,
      lastFailure: {
        eventId,
        attempts: 1,
        statusCode: 503,
        errorClass: 'http_status',
        at: NOW + 1,
        state: 'retrying',
        nextAttemptAt: NOW + 30_000,
      },
    });

    const [second] = await queue.claim({ ...pick, now: NOW + 30_000 });
    await queue.record(
      second,
      { result: 'failed', statusCode: 503, errorClass: 'http_status' },
      NOW + 30_001
    );
    expect(await streams.deliveryStatus(stream.id)).toEqual({
      pending: 0,
      lastFailure: {
        eventId,
        attempts: 2,
        statusCode: 503,
        errorClass: 'http_status',
        at: NOW + 30_001,
        state: 'failed',
      },
    });
  });

  it('fans out to a destination only the events about its subjects', async () => {
    const realmId = randomUUID();
    const userA = randomUUID();
    const userB = randomUUID();
    const signedOut = (userId: string): EmitEvent<typeof SIGNED_OUT> => ({
      type: SIGNED_OUT,
      realm: realmId,
      actor: { type: 'user', id: userId },
      subject: { type: 'user', id: userId },
      data: {},
    });
    const destinations = [
      { kind: SSF_DELIVERY_KIND, id: 'a', realmId, subjects: [{ type: 'user', id: userA }] },
      { kind: SSF_DELIVERY_KIND, id: 'none', realmId, subjects: [] },
      { kind: SSF_DELIVERY_KIND, id: 'all', realmId },
    ];
    await queue.fanOut({ kinds: [SSF_DELIVERY_KIND], destinations, now: NOW });
    const a = await store.emitInOwnTransaction(signedOut(userA));
    const b = await store.emitInOwnTransaction(signedOut(userB));
    await queue.fanOut({ kinds: [SSF_DELIVERY_KIND], destinations, now: NOW });

    expect((await queue.listForEvent(a)).map((row) => row.destinationId).sort()).toEqual([
      'a',
      'all',
    ]);
    expect((await queue.listForEvent(b)).map((row) => row.destinationId)).toEqual(['all']);
  });

  describe('a role holding only the delivery grants', () => {
    const ROLE = 'qauth_ssf_delivery';
    let delivery: Pool | undefined;
    let deliveryStreams: SsfStreamsRepository;

    beforeAll(async () => {
      if (!dockerUp || !ctx) return;
      await pool().query(`CREATE ROLE ${ROLE} LOGIN PASSWORD '${ROLE}'`);
      await pool().query(`GRANT USAGE ON SCHEMA public TO ${ROLE}`);
      for (const statement of eventDeliveryGrantStatements(ROLE)) await pool().query(statement);
      const url = new URL(ctx.connectionString);
      url.username = ROLE;
      url.password = ROLE;
      delivery = new Pool({ connectionString: url.toString(), max: 2 });
      deliveryStreams = createSsfStreamsRepository(drizzle(delivery) as unknown as Database);
    });

    afterAll(async () => {
      await delivery?.end();
    });

    it('lists the streams and reads the one it delivers to, and writes none', async () => {
      const { stream, key } = await streamOf();
      expect((await deliveryStreams.listDestinations()).map((row) => row.id)).toEqual([stream.id]);
      expect(await deliveryStreams.findForDelivery(stream.id)).toMatchObject({
        id: stream.id,
        active: true,
      });
      await expect(deliveryStreams.setStatus(key, 'disabled', null, NOW)).rejects.toMatchObject({
        cause: { code: '42501' },
      });
      await expect(
        delivery?.query(`SELECT client_secret_hash FROM oauth_clients`)
      ).rejects.toMatchObject({ code: '42501' });
    });
  });
});
