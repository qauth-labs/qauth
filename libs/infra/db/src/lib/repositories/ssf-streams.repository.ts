import { and, asc, eq, isNull, lte, or, sql } from 'drizzle-orm';

import type {
  Database,
  SsfStreamDeliveryStatus,
  SsfStreamDestination,
  SsfStreamForDelivery,
  SsfStreamKey,
  SsfStreamsRepository,
} from '../../types';
import { oauthConsents } from '../schema/consents';
import { oauthClients, realms, users } from '../schema/core';
import { eventDeliveries } from '../schema/event-deliveries';
import { ssfStreams, ssfStreamSubjects } from '../schema/ssf';
import { refreshTokens } from '../schema/tokens';

/**
 * The delivery route kind of the Shared Signals Framework transmitter: the
 * `destination_kind` of its rows in `event_deliveries` (issue #410).
 */
export const SSF_DELIVERY_KIND = 'ssf';

/**
 * The scope that makes an OAuth client a receiver (issue #410). A client that
 * loses it stops receiving: its stream is no longer listed or delivered to.
 */
export const SSF_RECEIVER_SCOPE = 'ssf:stream';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Refuse an id that is not a UUID before it reaches Postgres (22P02 → 500). */
function isUuid(value: string): boolean {
  return typeof value === 'string' && UUID_PATTERN.test(value);
}

function ownedBy(key: SsfStreamKey) {
  return and(
    eq(ssfStreams.id, key.streamId),
    eq(ssfStreams.realmId, key.realmId),
    eq(ssfStreams.receiverClientId, key.receiverClientId)
  );
}

const isKeyValid = (key: SsfStreamKey) =>
  isUuid(key.streamId) && isUuid(key.realmId) && isUuid(key.receiverClientId);

/**
 * Factory for the Shared Signals Framework streams (issue #410). See
 * {@link SsfStreamsRepository} for the guarantees.
 *
 * @param db - The server's database. The delivery route's reads
 *   (`listDestinations`, `findForDelivery`) also run as the delivery role's
 *   user, which `eventDeliveryGrantStatements` lets read these tables.
 */
export function createSsfStreamsRepository(db: Database): SsfStreamsRepository {
  return {
    async create(stream) {
      const [row] = await db
        .insert(ssfStreams)
        .values({
          ...(stream.id === undefined ? {} : { id: stream.id }),
          realmId: stream.realmId,
          receiverClientId: stream.receiverClientId,
          audience: stream.audience,
          eventsRequested: [...stream.eventsRequested],
          deliveryMethod: stream.deliveryMethod,
          endpointUrl: stream.endpointUrl,
          authorizationHeader: stream.authorizationHeader,
          description: stream.description,
        })
        .onConflictDoNothing({ target: [ssfStreams.realmId, ssfStreams.receiverClientId] })
        .returning();
      return row ?? null;
    },

    async find(key) {
      if (!isKeyValid(key)) return undefined;
      const [row] = await db.select().from(ssfStreams).where(ownedBy(key));
      return row;
    },

    async list(realmId, receiverClientId) {
      if (!isUuid(realmId) || !isUuid(receiverClientId)) return [];
      return db
        .select()
        .from(ssfStreams)
        .where(
          and(eq(ssfStreams.realmId, realmId), eq(ssfStreams.receiverClientId, receiverClientId))
        )
        .orderBy(asc(ssfStreams.createdAt), asc(ssfStreams.id));
    },

    async update(key, changes, now) {
      if (!isKeyValid(key)) return undefined;
      const [row] = await db
        .update(ssfStreams)
        .set({
          ...(changes.eventsRequested === undefined
            ? {}
            : { eventsRequested: [...changes.eventsRequested] }),
          ...(changes.deliveryMethod === undefined
            ? {}
            : { deliveryMethod: changes.deliveryMethod }),
          ...(changes.endpointUrl === undefined ? {} : { endpointUrl: changes.endpointUrl }),
          ...(changes.authorizationHeader === undefined
            ? {}
            : { authorizationHeader: changes.authorizationHeader }),
          ...(changes.description === undefined ? {} : { description: changes.description }),
          updatedAt: now,
        })
        .where(ownedBy(key))
        .returning();
      return row;
    },

    async remove(key) {
      if (!isKeyValid(key)) return false;
      const result = await db.delete(ssfStreams).where(ownedBy(key));
      return (result.rowCount ?? 0) > 0;
    },

    async setStatus(key, status, reason, now) {
      if (!isKeyValid(key)) return undefined;
      const [row] = await db
        .update(ssfStreams)
        .set({ status, statusReason: reason, updatedAt: now })
        .where(ownedBy(key))
        .returning();
      return row;
    },

    async addSubject(streamId, subject, maxSubjects) {
      if (!isUuid(streamId))
        throw new TypeError('ssfStreams.addSubject: a stream id must be a UUID');
      return db.transaction(async (tx) => {
        // The stream's row lock makes the count and the insert one step, so
        // two adds at once cannot both pass a stream that has one place left.
        // No row: the stream was deleted since the caller found it.
        const { rows: locked } = await tx.execute(
          sql`select 1 from ${ssfStreams} where ${ssfStreams.id} = ${streamId} for update`
        );
        if (locked.length === 0) return 'missing';
        const [{ count }] = await tx
          .select({ count: sql<number>`count(*)::int` })
          .from(ssfStreamSubjects)
          .where(eq(ssfStreamSubjects.streamId, streamId));
        const [present] = await tx
          .select({ key: ssfStreamSubjects.subjectKey })
          .from(ssfStreamSubjects)
          .where(
            and(
              eq(ssfStreamSubjects.streamId, streamId),
              eq(ssfStreamSubjects.subjectKey, subject.subjectKey)
            )
          );
        if (present) return 'present';
        if (count >= maxSubjects) return 'full';
        await tx
          .insert(ssfStreamSubjects)
          .values({
            streamId,
            subjectKey: subject.subjectKey,
            subject: { ...subject.subject },
            eventSubjectType: subject.eventSubject?.type ?? null,
            eventSubjectId: subject.eventSubject?.id ?? null,
            verified: subject.verified,
          })
          .onConflictDoNothing();
        return 'added';
      });
    },

    async removeSubject(streamId, subjectKey) {
      if (!isUuid(streamId)) return false;
      const result = await db
        .delete(ssfStreamSubjects)
        .where(
          and(
            eq(ssfStreamSubjects.streamId, streamId),
            eq(ssfStreamSubjects.subjectKey, subjectKey)
          )
        );
      return (result.rowCount ?? 0) > 0;
    },

    async listSubjects(streamId) {
      if (!isUuid(streamId)) return [];
      return db
        .select()
        .from(ssfStreamSubjects)
        .where(eq(ssfStreamSubjects.streamId, streamId))
        .orderBy(asc(ssfStreamSubjects.createdAt), asc(ssfStreamSubjects.subjectKey));
    },

    async isRelatedUser(realmId, receiverClientId, userId, now) {
      if (![realmId, receiverClientId, userId].every(isUuid)) return false;
      const { rows } = await db.execute<{ related: boolean }>(sql`
        select exists (
          select 1 from ${oauthConsents}
          where ${oauthConsents.realmId} = ${realmId}
            and ${oauthConsents.userId} = ${userId}
            and ${oauthConsents.oauthClientId} = ${receiverClientId}
            and ${oauthConsents.revokedAt} is null
        ) or exists (
          select 1 from ${refreshTokens}
          join ${users} on ${users.id} = ${refreshTokens.userId}
            and ${users.realmId} = ${realmId}
          where ${refreshTokens.userId} = ${userId}
            and ${refreshTokens.oauthClientId} = ${receiverClientId}
            and not ${refreshTokens.revoked}
            and ${refreshTokens.expiresAt} > ${now}
        ) as "related"
      `);
      return rows[0]?.related === true;
    },

    async listDestinations() {
      const { rows } = await db.execute<{
        id: string;
        realm_id: string;
        status: 'enabled' | 'paused';
        audience: string;
        events_requested: string[];
        subject_type: string | null;
        subject_id: string | null;
      }>(sql`
        select ${ssfStreams.id} as "id", ${ssfStreams.realmId} as "realm_id",
          ${ssfStreams.status} as "status", ${ssfStreams.audience} as "audience",
          ${ssfStreams.eventsRequested} as "events_requested",
          ${ssfStreamSubjects.eventSubjectType} as "subject_type",
          ${ssfStreamSubjects.eventSubjectId} as "subject_id"
        from ${ssfStreams}
        join ${realms} on ${realms.id} = ${ssfStreams.realmId}
          and ${realms.ssfTransmitterEnabled}
        join ${oauthClients} on ${oauthClients.id} = ${ssfStreams.receiverClientId}
          and ${oauthClients.enabled} and not ${oauthClients.suspended}
          and ${oauthClients.scopes} ? ${SSF_RECEIVER_SCOPE}
        left join ${ssfStreamSubjects} on ${ssfStreamSubjects.streamId} = ${ssfStreams.id}
          and ${ssfStreamSubjects.eventSubjectType} is not null
        where ${ssfStreams.status} in ('enabled', 'paused')
        order by ${ssfStreams.id}
      `);
      const byId = new Map<
        string,
        SsfStreamDestination & { subjects: { type: string; id: string }[] }
      >();
      for (const row of rows) {
        let destination = byId.get(row.id);
        if (destination === undefined) {
          destination = {
            id: row.id,
            realmId: row.realm_id,
            status: row.status,
            audience: row.audience,
            eventsRequested: row.events_requested,
            subjects: [],
          };
          byId.set(row.id, destination);
        }
        if (row.subject_type !== null && row.subject_id !== null) {
          destination.subjects.push({ type: row.subject_type, id: row.subject_id });
        }
      }
      return [...byId.values()];
    },

    async findForDelivery(streamId): Promise<SsfStreamForDelivery | undefined> {
      if (!isUuid(streamId)) return undefined;
      const [row] = await db
        .select({
          stream: ssfStreams,
          active: sql<boolean>`(${realms.ssfTransmitterEnabled} and ${oauthClients.enabled} and not ${oauthClients.suspended} and ${oauthClients.scopes} ? ${SSF_RECEIVER_SCOPE})`,
          issuer: realms.issuer,
        })
        .from(ssfStreams)
        .innerJoin(realms, eq(realms.id, ssfStreams.realmId))
        .innerJoin(oauthClients, eq(oauthClients.id, ssfStreams.receiverClientId))
        .where(eq(ssfStreams.id, streamId));
      return row === undefined
        ? undefined
        : { ...row.stream, active: row.active, issuer: row.issuer };
    },

    async deliveryStatus(streamId, now): Promise<SsfStreamDeliveryStatus> {
      if (!isUuid(streamId)) return { pending: 0 };
      const ofStream = and(
        eq(eventDeliveries.destinationKind, SSF_DELIVERY_KIND),
        eq(eventDeliveries.destinationId, streamId)
      );
      const [{ pending }] = await db
        .select({ pending: sql<number>`count(*)::int` })
        .from(eventDeliveries)
        .where(and(ofStream, eq(eventDeliveries.status, 'pending')));
      const [failure] = await db
        .select({
          eventId: eventDeliveries.eventId,
          attempts: eventDeliveries.attemptCount,
          statusCode: eventDeliveries.lastStatusCode,
          errorClass: eventDeliveries.lastErrorClass,
          at: eventDeliveries.updatedAt,
          status: eventDeliveries.status,
          nextAttemptAt: eventDeliveries.nextAttemptAt,
        })
        .from(eventDeliveries)
        .where(
          and(
            ofStream,
            sql`${eventDeliveries.lastErrorClass} is not null`,
            // A row an attempt is running on shows the claim, not a failure:
            // its count includes the running attempt and its times are the
            // lease's.
            or(isNull(eventDeliveries.lockedUntil), lte(eventDeliveries.lockedUntil, now))
          )
        )
        .orderBy(sql`${eventDeliveries.updatedAt} desc`, sql`${eventDeliveries.id} desc`)
        .limit(1);
      if (failure === undefined || failure.errorClass === null) return { pending };
      const retrying = failure.status === 'pending';
      return {
        pending,
        lastFailure: {
          eventId: failure.eventId,
          attempts: failure.attempts,
          statusCode: failure.statusCode,
          errorClass: failure.errorClass,
          at: failure.at,
          state: retrying ? 'retrying' : 'failed',
          ...(retrying ? { nextAttemptAt: failure.nextAttemptAt } : {}),
        },
      };
    },

    async enqueueForEvent(tx, request) {
      if (!isUuid(request.streamId) || !isUuid(request.eventId)) {
        throw new TypeError('ssfStreams.enqueueForEvent: the stream and event ids must be UUIDs');
      }
      // `events_own_row` returns the event only to the transaction that wrote
      // it (migration 0033), so a stream cannot be handed another event, and
      // only a stream of the event's own realm gets the row.
      const result = await tx.execute(sql`
        insert into ${eventDeliveries} (destination_kind, destination_id, event_id, realm_id,
          event_xid, event_seq, event_time, next_attempt_at, created_at, updated_at)
        select ${SSF_DELIVERY_KIND}, ${request.streamId}, "own"."id", "own"."realm_id",
          "own"."xid", "own"."seq", "own"."time", ${request.now}, ${request.now}, ${request.now}
        from events_own_row(${request.eventId}::uuid) as "own"
        where exists (
          select 1 from ${ssfStreams}
          where ${ssfStreams.id} = ${request.streamId} and ${ssfStreams.realmId} = "own"."realm_id"
        )
        on conflict on constraint event_deliveries_event_destination_unique do nothing
      `);
      return (result.rowCount ?? 0) > 0;
    },
  };
}
