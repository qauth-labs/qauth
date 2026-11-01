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
 * fan-out's subject filter gives a stream only events about its subjects;
 * a user is related to a receiver only as the token endpoint reads its
 * tokens, a resource server's users included (#540); the sweep ends a user
 * subject only once its relation has ended and no event about the user can
 * still reach the stream; and a role holding only the delivery grants can
 * read what the route reads.
 *
 * Requires Docker; self-skips without it, same as the sibling suites.
 */
import { randomUUID } from 'node:crypto';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import { NOT_VALID_BEFORE_MARGIN_MS } from '@qauth-labs/shared-validation';
import { drizzle } from 'drizzle-orm/node-postgres';
import { Pool } from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import type {
  Database,
  EmitEvent,
  EventDeliveriesRepository,
  EventDeliveryDestination,
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
    // A container of its own: a case below creates roles, which are
    // cluster-wide and outlive the database, so on a shared server their
    // fixed names would meet the next suite's.
    ctx = await setupIntegrationDb({ privateContainer: true });
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
    const name = `realm-${randomUUID()}`;
    const { rows } = await pool().query<{ id: string }>(
      `INSERT INTO realms (name, ssf_transmitter_enabled, issuer) VALUES ($1, $2, $3) RETURNING id`,
      [name, options.ssf ?? true, `https://${name}.example.com`]
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

  it('answers missing, not a foreign key error, for a stream deleted since it was found', async () => {
    const { stream, key } = await streamOf();
    expect(await streams.remove(key)).toBe(true);
    expect(
      await streams.addSubject(
        stream.id,
        { subjectKey: 'gone', subject: { format: 'opaque' }, eventSubject: null, verified: true },
        3
      )
    ).toBe('missing');
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
      audience: enabled.stream.audience,
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
    expect(await streams.deliveryStatus(stream.id, NOW)).toEqual({ pending: 0 });
    const { eventId } = await verify(realmId, stream.id);
    expect(await streams.deliveryStatus(stream.id, NOW)).toEqual({ pending: 1 });

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
    expect(await streams.deliveryStatus(stream.id, NOW + 1)).toEqual({
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

    // While the next attempt runs, the row shows its claim, not a failure: it
    // is left out, rather than shown with the running attempt counted and the
    // lease's times.
    const [second] = await queue.claim({ ...pick, now: NOW + 30_000 });
    expect(await streams.deliveryStatus(stream.id, NOW + 30_000)).toEqual({ pending: 1 });
    // A lease that ran out (its worker died) shows again.
    expect(
      (await streams.deliveryStatus(stream.id, NOW + 30_000 + 60_000)).lastFailure
    ).toMatchObject({ attempts: 2, errorClass: 'http_status' });

    await queue.record(
      second,
      { result: 'failed', statusCode: 503, errorClass: 'http_status' },
      NOW + 30_001
    );
    expect(await streams.deliveryStatus(stream.id, NOW + 30_001)).toEqual({
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

  it('relates a user to a receiver by an active consent or a live refresh token only (#540)', async () => {
    const realmId = await realm();
    const receiver = await client(realmId);
    const other = await client(realmId);
    const user = async (inRealm = realmId) =>
      (
        await pool().query<{ id: string }>(
          `INSERT INTO users (realm_id) VALUES ($1) RETURNING id::text AS id`,
          [inRealm]
        )
      ).rows[0].id;
    const consent = (userId: string, clientRowId: string, revokedAt: number | null = null) =>
      pool().query(
        `INSERT INTO oauth_consents (realm_id, user_id, oauth_client_id, revoked_at)
         VALUES ($1, $2, $3, $4)`,
        [realmId, userId, clientRowId, revokedAt]
      );
    const refresh = (
      userId: string,
      clientRowId: string,
      options: { expiresAt?: number; revoked?: boolean } = {}
    ) =>
      pool().query(
        `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, family_created_at, expires_at, revoked)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          randomUUID().replaceAll('-', '').padEnd(64, '0'),
          userId,
          clientRowId,
          NOW - 1000,
          options.expiresAt ?? NOW + 60_000,
          options.revoked ?? false,
        ]
      );
    const related = (userId: string) => streams.isRelatedUser(realmId, receiver.id, userId, NOW);

    const consented = await user();
    await consent(consented, receiver.id);
    const withToken = await user();
    await refresh(withToken, receiver.id);
    const withdrawn = await user();
    await consent(withdrawn, receiver.id, NOW - 1);
    const revokedToken = await user();
    await refresh(revokedToken, receiver.id, { revoked: true });
    const expiredToken = await user();
    await refresh(expiredToken, receiver.id, { expiresAt: NOW });
    const otherClients = await user();
    await consent(otherClients, other.id);
    await refresh(otherClients, other.id);
    const stranger = await user();

    expect(await related(consented)).toBe(true);
    expect(await related(withToken)).toBe(true);
    for (const userId of [withdrawn, revokedToken, expiredToken, otherClients, stranger]) {
      expect(await related(userId), userId).toBe(false);
    }
    expect(await related(randomUUID())).toBe(false);
    expect(await related('not-a-uuid')).toBe(false);
    // The same user asked about from another realm is no user of it.
    const elsewhere = await realm();
    expect(await streams.isRelatedUser(elsewhere, receiver.id, consented, NOW)).toBe(false);
    expect(await streams.isRelatedUser(elsewhere, receiver.id, withToken, NOW)).toBe(false);
  });

  it('relates no disabled user, and a refresh token only while its family lives (#540)', async () => {
    const realmId = await realm();
    const receiver = await client(realmId);
    // The token endpoint's rule (ADR-019 Decision 3): with `sso_max_lifespan`
    // set, a family ends at its start plus the limit, and no later than the
    // browser session that started it.
    const LIFESPAN_SECONDS = 3600;
    await pool().query(`UPDATE realms SET sso_max_lifespan = $2 WHERE id = $1`, [
      realmId,
      LIFESPAN_SECONDS,
    ]);
    const user = async (enabled = true) =>
      (
        await pool().query<{ id: string }>(
          `INSERT INTO users (realm_id, enabled) VALUES ($1, $2) RETURNING id::text AS id`,
          [realmId, enabled]
        )
      ).rows[0].id;
    const refresh = (
      userId: string,
      family: { createdAt: number; sessionExpiresAt?: number | null }
    ) =>
      pool().query(
        `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, family_created_at,
           family_session_expires_at, expires_at, revoked)
         VALUES ($1, $2, $3, $4, $5, $6, false)`,
        [
          randomUUID().replaceAll('-', '').padEnd(64, '0'),
          userId,
          receiver.id,
          family.createdAt,
          family.sessionExpiresAt ?? null,
          NOW + 60_000,
        ]
      );
    const related = (userId: string) => streams.isRelatedUser(realmId, receiver.id, userId, NOW);

    // Within both bounds: the normal case, related.
    const live = await user();
    await refresh(live, { createdAt: NOW - 1000, sessionExpiresAt: NOW + 1000 });
    // No browser session started it: its start plus the limit alone.
    const noSession = await user();
    await refresh(noSession, { createdAt: NOW - 1000 });
    // Past the limit, though the token itself has not expired.
    const pastLimit = await user();
    await refresh(pastLimit, { createdAt: NOW - LIFESPAN_SECONDS * 1000 });
    // Past the end of the browser session that started it.
    const pastSession = await user();
    await refresh(pastSession, { createdAt: NOW - 1000, sessionExpiresAt: NOW });
    // A disabled user, by a live token or an active consent.
    const disabled = await user(false);
    await refresh(disabled, { createdAt: NOW - 1000 });
    await pool().query(
      `INSERT INTO oauth_consents (realm_id, user_id, oauth_client_id) VALUES ($1, $2, $3)`,
      [realmId, disabled, receiver.id]
    );

    expect(await related(live)).toBe(true);
    expect(await related(noSession)).toBe(true);
    for (const userId of [pastLimit, pastSession, disabled]) {
      expect(await related(userId), userId).toBe(false);
    }

    // A realm that sets no limit bounds neither: the token endpoint keeps
    // such a family alive by its tokens' own expiry.
    await pool().query(`UPDATE realms SET sso_max_lifespan = NULL WHERE id = $1`, [realmId]);
    expect(await related(pastLimit)).toBe(true);
    expect(await related(pastSession)).toBe(true);
    expect(await related(disabled)).toBe(false);
  });

  it('relates a user enabled again by no refresh token issued before the disablement (#748)', async () => {
    const realmId = await realm();
    const receiver = await client(realmId);
    // Disabled at DISABLED_AT and enabled again since. The trigger of
    // migration 0044 sets the time on an UPDATE only, so the row is inserted
    // with it.
    const DISABLED_AT = NOW - 60_000;
    const user = async (notValidBefore: number | null) =>
      (
        await pool().query<{ id: string }>(
          `INSERT INTO users (realm_id, not_valid_before) VALUES ($1, $2) RETURNING id::text AS id`,
          [realmId, notValidBefore]
        )
      ).rows[0].id;
    const refresh = (userId: string, issued: { familyCreatedAt: number; createdAt: number }) =>
      pool().query(
        `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, family_created_at, created_at, expires_at, revoked)
         VALUES ($1, $2, $3, $4, $5, $6, false)`,
        [
          randomUUID().replaceAll('-', '').padEnd(64, '0'),
          userId,
          receiver.id,
          issued.familyCreatedAt,
          issued.createdAt,
          NOW + 60_000,
        ]
      );
    const related = (userId: string) => streams.isRelatedUser(realmId, receiver.id, userId, NOW);

    // Signed in again after the account was enabled: the token endpoint
    // takes its token, so it relates the user.
    const signedInAgain = await user(DISABLED_AT);
    await refresh(signedInAgain, {
      familyCreatedAt: DISABLED_AT + NOT_VALID_BEFORE_MARGIN_MS + 1,
      createdAt: DISABLED_AT + 30_000,
    });
    // Never disabled: the time is null, and an old token still counts.
    const neverDisabled = await user(null);
    await refresh(neverDisabled, { familyCreatedAt: NOW - 600_000, createdAt: NOW - 600_000 });
    // Issued before the disablement and unused while it lasted.
    const heldBefore = await user(DISABLED_AT);
    await refresh(heldBefore, {
      familyCreatedAt: DISABLED_AT - 5_000,
      createdAt: DISABLED_AT - 5_000,
    });
    // Issued within the margin after it.
    const withinMargin = await user(DISABLED_AT);
    await refresh(withinMargin, {
      familyCreatedAt: DISABLED_AT + NOT_VALID_BEFORE_MARGIN_MS,
      createdAt: DISABLED_AT + NOT_VALID_BEFORE_MARGIN_MS,
    });
    // Rotated after the account was enabled again, from a family that began
    // before the disablement: the family's start counts.
    const rotatedFromBefore = await user(DISABLED_AT);
    await refresh(rotatedFromBefore, {
      familyCreatedAt: DISABLED_AT - 5_000,
      createdAt: DISABLED_AT + 30_000,
    });

    expect(await related(signedInAgain)).toBe(true);
    expect(await related(neverDisabled)).toBe(true);
    for (const userId of [heldBefore, withinMargin, rotatedFromBefore]) {
      expect(await related(userId), userId).toBe(false);
    }
    // An active consent still relates the user: disabling withdraws none.
    await pool().query(
      `INSERT INTO oauth_consents (realm_id, user_id, oauth_client_id) VALUES ($1, $2, $3)`,
      [realmId, heldBefore, receiver.id]
    );
    expect(await related(heldBefore)).toBe(true);
  });

  /** A client of `realmId` with `audience` (`null` for none); its row id and `client_id`. */
  async function clientWithAudience(realmId: string, audience: string[] | null) {
    const clientId = `client-${randomUUID()}`;
    const { rows } = await pool().query<{ id: string }>(
      `INSERT INTO oauth_clients (realm_id, client_id, client_secret_hash, name, redirect_uris, scopes, audience)
       VALUES ($1, $2, 'x', 'client', '[]', '["ssf:stream"]', $3) RETURNING id`,
      [realmId, clientId, audience === null ? null : JSON.stringify(audience)]
    );
    return { id: rows[0].id, clientId };
  }

  /** A user of `realmId`. */
  async function userOf(realmId: string, enabled = true): Promise<string> {
    const { rows } = await pool().query<{ id: string }>(
      `INSERT INTO users (realm_id, enabled) VALUES ($1, $2) RETURNING id::text AS id`,
      [realmId, enabled]
    );
    return rows[0].id;
  }

  /** A refresh token issued to `clientRowId` for `userId`, live at NOW unless told otherwise. */
  function refreshTokenOf(
    userId: string,
    clientRowId: string,
    options: { resource?: string[]; revoked?: boolean; familyCreatedAt?: number } = {}
  ) {
    return pool().query(
      `INSERT INTO refresh_tokens (token_hash, user_id, oauth_client_id, family_created_at,
         expires_at, revoked, resource)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        randomUUID().replaceAll('-', '').padEnd(64, '0'),
        userId,
        clientRowId,
        options.familyCreatedAt ?? NOW - 1000,
        NOW + 60_000,
        options.revoked ?? false,
        JSON.stringify(options.resource ?? []),
      ]
    );
  }

  // Decided 2026-10-31: a resource server relates to the users who hold a
  // live token for it. A receiver serves the values of its `audience`, the
  // column introspection reads the same way, but never a `urn:qauth:aud:`
  // value nor the realm's issuer, which every SSF receiver lists to manage
  // its stream.
  it('relates a user to a resource-server receiver by a live refresh token for its audience (#540)', async () => {
    const realmId = await realm();
    const { rows } = await pool().query<{ issuer: string }>(
      `SELECT issuer FROM realms WHERE id = $1`,
      [realmId]
    );
    const issuer = rows[0].issuer;
    const API = 'https://api.notes.example';
    const ADMIN = 'urn:qauth:aud:admin:v1-rc.0';
    const LIFESPAN_SECONDS = 3600;
    await pool().query(`UPDATE realms SET sso_max_lifespan = $2 WHERE id = $1`, [
      realmId,
      LIFESPAN_SECONDS,
    ]);
    const resourceServer = await clientWithAudience(realmId, [issuer, API, ADMIN]);
    // The clients users sign in through: one with no audience, one whose
    // default audience is the API, one whose default is the issuer only.
    const app = await clientWithAudience(realmId, null);
    const apiDefault = await clientWithAudience(realmId, [ADMIN, API]);
    const issuerDefault = await clientWithAudience(realmId, [issuer]);
    const related = (userId: string, inRealm = realmId, receiverId = resourceServer.id) =>
      streams.isRelatedUser(inRealm, receiverId, userId, NOW);

    // A token whose RFC 8707 resource is the API.
    const byResource = await userOf(realmId);
    await refreshTokenOf(byResource, app.id, { resource: [API] });
    // A token with no resource, of a client whose default audience is the API.
    const byDefault = await userOf(realmId);
    await refreshTokenOf(byDefault, apiDefault.id);
    // A token for another resource server.
    const elsewhere = await userOf(realmId);
    await refreshTokenOf(elsewhere, app.id, { resource: ['https://api.other.example'] });
    // A token whose audience is the issuer: QAuth itself, not the receiver.
    const forIssuer = await userOf(realmId);
    await refreshTokenOf(forIssuer, issuerDefault.id);
    await refreshTokenOf(forIssuer, app.id, { resource: [issuer] });
    // A token for a QAuth API family: never the receiver's.
    const forAdmin = await userOf(realmId);
    await refreshTokenOf(forAdmin, app.id, { resource: [ADMIN] });
    // A token with no resource of a client with no audience: `aud` is that
    // client's own client_id.
    const ownClientId = await userOf(realmId);
    await refreshTokenOf(ownClientId, app.id);
    // The C2 liveness rules hold on this path too.
    const revoked = await userOf(realmId);
    await refreshTokenOf(revoked, app.id, { resource: [API], revoked: true });
    const familyEnded = await userOf(realmId);
    await refreshTokenOf(familyEnded, app.id, {
      resource: [API],
      familyCreatedAt: NOW - LIFESPAN_SECONDS * 1000,
    });
    const disabled = await userOf(realmId, false);
    await refreshTokenOf(disabled, app.id, { resource: [API] });

    expect(await related(byResource)).toBe(true);
    expect(await related(byDefault)).toBe(true);
    for (const userId of [
      elsewhere,
      forIssuer,
      forAdmin,
      ownClientId,
      revoked,
      familyEnded,
      disabled,
    ]) {
      expect(await related(userId), userId).toBe(false);
    }
    // A receiver that is no resource server for the API relates no one by it.
    const plain = await clientWithAudience(realmId, [issuer]);
    expect(await related(byResource, realmId, plain.id)).toBe(false);

    // Another realm: a resource server there with the same audience relates
    // no user of this realm, and this realm's receiver, asked about from
    // there, relates no one either.
    const otherRealm = await realm();
    const otherServer = await clientWithAudience(otherRealm, [API]);
    expect(await related(byResource, otherRealm, otherServer.id)).toBe(false);
    expect(await related(byResource, otherRealm)).toBe(false);
    const theirs = await userOf(otherRealm);
    const theirApp = await clientWithAudience(otherRealm, null);
    await refreshTokenOf(theirs, theirApp.id, { resource: [API] });
    expect(await related(theirs)).toBe(false);
    expect(await related(theirs, otherRealm, otherServer.id)).toBe(true);
  });

  // Decided 2026-10-31: a user subject ends when its relation ends, by a
  // sweep, once no event about the user can still reach the stream.
  it('sweeps a user subject once its relation has ended and nothing about the user can still reach the stream (#540)', async () => {
    const { realmId, receiver, stream } = await streamOf();
    // A second receiver's stream in the same realm.
    const otherReceiver = await client(realmId);
    const otherStream = await streams.create(newStream(realmId, otherReceiver.id));
    if (!otherStream) throw new Error('no stream');
    const other = { stream: otherStream };
    const consent = (userId: string) =>
      pool().query(
        `INSERT INTO oauth_consents (realm_id, user_id, oauth_client_id) VALUES ($1, $2, $3)`,
        [realmId, userId, receiver.id]
      );

    const related = await userOf(realmId);
    await consent(related);
    const settled = await userOf(realmId);
    const pending = await userOf(realmId);
    const unread = await userOf(realmId);
    const delivered = await userOf(realmId);
    const pendingElsewhere = await userOf(realmId);
    const disabled = await userOf(realmId, false);
    await consent(disabled);
    const gone = randomUUID();
    const users = [related, settled, pending, unread, delivered, pendingElsewhere, disabled, gone];

    const add = (
      streamId: string,
      key: string,
      eventSubject: { type: string; id: string } | null
    ) =>
      streams.addSubject(
        streamId,
        { subjectKey: key, subject: { format: 'opaque', id: key }, eventSubject, verified: true },
        100
      );
    for (const userId of users) await add(stream.id, userId, { type: 'user', id: userId });
    await add(stream.id, 'client', { type: 'client', id: 'notes-app' });
    await add(stream.id, 'unplaced', null);
    await add(other.stream.id, pendingElsewhere, { type: 'user', id: pendingElsewhere });

    const destinations: EventDeliveryDestination[] = [
      {
        kind: SSF_DELIVERY_KIND,
        id: stream.id,
        realmId,
        subjects: users.map((id) => ({ type: 'user', id })),
      },
      {
        kind: SSF_DELIVERY_KIND,
        id: other.stream.id,
        realmId,
        subjects: [{ type: 'user', id: pendingElsewhere }],
      },
    ];
    const signedOut = (userId: string) =>
      store.emitInOwnTransaction({
        type: SIGNED_OUT,
        realm: realmId,
        actor: { type: 'user', id: userId },
        subject: { type: 'user', id: userId },
        data: {},
      });
    // The realm's fan-out position, then events it reads past.
    await queue.fanOut({ kinds: [SSF_DELIVERY_KIND], destinations, now: NOW });
    await signedOut(pending);
    const deliveredEvent = await signedOut(delivered);
    // Delivered to this stream, still pending on the other one only.
    const elsewhereEvent = await signedOut(pendingElsewhere);
    await queue.fanOut({ kinds: [SSF_DELIVERY_KIND], destinations, now: NOW });
    await pool().query(
      `UPDATE event_deliveries SET status = 'delivered', finished_at = $3
       WHERE (event_id = $1 OR (event_id = $2 AND destination_id = $4))`,
      [deliveredEvent, elsewhereEvent, NOW, stream.id]
    );
    // An event past the position: the fan-out has not read it yet.
    await signedOut(unread);

    const kept = async (streamId: string) =>
      (
        await pool().query<{ subject_key: string }>(
          `SELECT subject_key FROM ssf_stream_subjects WHERE stream_id = $1`,
          [streamId]
        )
      ).rows
        .map((row) => row.subject_key)
        .sort();

    // Only the unrelated users nothing waits on: never a related one, one with
    // an event to fan out or a delivery pending, a client or an unplaced one.
    expect(await streams.sweepUserSubjects(NOW)).toBe(5);
    expect(await kept(stream.id)).toEqual(['client', 'unplaced', related, pending, unread].sort());
    // The other stream's receiver is not related to its user either; its
    // delivery is still pending there.
    expect(await kept(other.stream.id)).toEqual([pendingElsewhere]);
    // Repeating it deletes nothing new.
    expect(await streams.sweepUserSubjects(NOW)).toBe(0);

    // Once the pending delivery finishes and the fan-out reads the last
    // event, those subjects end too.
    await pool().query(
      `UPDATE event_deliveries SET status = 'failed', finished_at = $1 WHERE status = 'pending'`,
      [NOW]
    );
    await queue.fanOut({ kinds: [SSF_DELIVERY_KIND], destinations, now: NOW });
    await pool().query(
      `UPDATE event_deliveries SET status = 'delivered', finished_at = $1 WHERE status = 'pending'`,
      [NOW]
    );
    expect(await streams.sweepUserSubjects(NOW)).toBe(3);
    expect(await kept(stream.id)).toEqual(['client', 'unplaced', related].sort());
    expect(await kept(other.stream.id)).toEqual([]);
  });

  it('reads a type rule: the client as the subject, no subject filter, or one client only (#540)', async () => {
    const realmId = randomUUID();
    const userId = randomUUID();
    const API_KEY_REVOKED = 'urn:qauth:event:api_key.revoked:v1-rc.0';
    const CONSENT_REVOKED = 'urn:qauth:event:consent.revoked:v1-rc.0';
    const KEY_RETIRED = 'urn:qauth:event:key.emergency_retired:v1-rc.0';
    const destinations: EventDeliveryDestination[] = [
      {
        kind: SSF_DELIVERY_KIND,
        id: 'client-a',
        realmId,
        subjects: [{ type: 'client', id: 'cli-a' }],
        typeRules: { [API_KEY_REVOKED]: { subjectFrom: 'client' } },
      },
      {
        kind: SSF_DELIVERY_KIND,
        id: 'client-a-no-rule',
        realmId,
        subjects: [{ type: 'client', id: 'cli-a' }],
      },
      {
        kind: SSF_DELIVERY_KIND,
        id: 'own-client-a',
        realmId,
        subjects: [{ type: 'user', id: userId }],
        typeRules: { [CONSENT_REVOKED]: { clientId: 'cli-a' } },
      },
      {
        kind: SSF_DELIVERY_KIND,
        id: 'realm-wide',
        realmId,
        subjects: [],
        typeRules: { [KEY_RETIRED]: { subjectFrom: 'none' } },
      },
    ];
    await queue.fanOut({ kinds: [SSF_DELIVERY_KIND], destinations, now: NOW });
    const keyRevoked = await store.emitInOwnTransaction({
      type: API_KEY_REVOKED,
      realm: realmId,
      actor: { type: 'user', id: userId },
      subject: { type: 'api_key', id: randomUUID() },
      client: { id: 'cli-a' },
      data: {},
    });
    const consentRevoked = (clientId: string) =>
      store.emitInOwnTransaction({
        type: CONSENT_REVOKED,
        realm: realmId,
        actor: { type: 'user', id: userId },
        subject: { type: 'user', id: userId },
        client: { id: clientId },
        data: { consentId: randomUUID() },
      });
    const viaA = await consentRevoked('cli-a');
    const viaB = await consentRevoked('cli-b');
    const retired = await store.emitInOwnTransaction({
      type: KEY_RETIRED,
      realm: realmId,
      actor: { type: 'operator_cli', id: 'root' },
      data: { keyId: 'kid-1', purpose: 'token_signing' },
    });
    await queue.fanOut({ kinds: [SSF_DELIVERY_KIND], destinations, now: NOW });

    const to = async (eventId: string) =>
      (await queue.listForEvent(eventId)).map((row) => row.destinationId).sort();
    expect(await to(keyRevoked)).toEqual(['client-a']);
    expect(await to(viaA)).toEqual(['own-client-a']);
    expect(await to(viaB)).toEqual([]);
    expect(await to(retired)).toEqual(['realm-wide']);
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
      await streams.addSubject(
        stream.id,
        {
          subjectKey: 'user',
          subject: { format: 'email', email: 'someone@example.com' },
          eventSubject: { type: 'user', id: 'u1' },
          verified: true,
        },
        10
      );
      expect(await deliveryStreams.listDestinations()).toEqual([
        expect.objectContaining({ id: stream.id, subjects: [{ type: 'user', id: 'u1' }] }),
      ]);
      // The subject as the receiver sent it, an email address say, is not the
      // role's to read: only the event subject it stands for.
      await expect(
        delivery?.query(`SELECT subject FROM ssf_stream_subjects`)
      ).rejects.toMatchObject({ code: '42501' });
      expect(await deliveryStreams.findForDelivery(stream.id)).toMatchObject({
        id: stream.id,
        active: true,
        issuer: expect.stringMatching(/^https:\/\/realm-.*\.example\.com$/),
      });
      await expect(deliveryStreams.setStatus(key, 'disabled', null, NOW)).rejects.toMatchObject({
        cause: { code: '42501' },
      });
      await expect(
        delivery?.query(`SELECT client_secret_hash FROM oauth_clients`)
      ).rejects.toMatchObject({ code: '42501' });
      // Before each attempt the route asks whether the stream still has the
      // event's subject, through the same grants.
      expect(await deliveryStreams.hasSubject(stream.id, { type: 'user', id: 'u1' })).toBe(true);
      expect(await deliveryStreams.hasSubject(stream.id, { type: 'user', id: 'u2' })).toBe(false);
      expect(await deliveryStreams.hasSubject(stream.id, { type: 'client', id: 'u1' })).toBe(false);
      expect(await deliveryStreams.hasSubject(randomUUID(), { type: 'user', id: 'u1' })).toBe(
        false
      );
      await streams.removeSubject(stream.id, 'user');
      expect(await deliveryStreams.hasSubject(stream.id, { type: 'user', id: 'u1' })).toBe(false);
    });
  });
});
