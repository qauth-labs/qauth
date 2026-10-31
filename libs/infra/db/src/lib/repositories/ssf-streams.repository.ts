import { RESERVED_AUDIENCE_PREFIX } from '@qauth-labs/shared-validation';
import { and, asc, eq, isNull, lte, or, type SQL, sql } from 'drizzle-orm';

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
import { eventDeliveries, eventDeliveryPositions } from '../schema/event-deliveries';
import { events } from '../schema/events';
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
 * An audience in QAuth's reserved `urn:qauth:aud:` namespace, as
 * `isReservedAudience` matches it: after any leading white space, in any case
 * (Postgres `~*`).
 */
const RESERVED_AUDIENCE_SQL_PATTERN = `^\\s*${RESERVED_AUDIENCE_PREFIX}`;

/** The text of a UUID, in either case: what a `uuid` cast accepts. */
const UUID_TEXT_SQL_PATTERN = '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

/** What {@link relatedUserCondition} relates: SQL expressions of the statement it is put in. */
interface RelatedUserTarget {
  /** The realm, a `uuid`. */
  readonly realmId: SQL;
  /** The receiver's `oauth_clients.id`, a `uuid`. */
  readonly receiverClientId: SQL;
  /** The user's id, a `uuid`; `null` names no user. */
  readonly userId: SQL;
}

/**
 * Whether a user is related to a receiver at `now` (#540): the condition
 * `isRelatedUser` answers and the subject sweep deletes on, as one SQL
 * condition over the expressions of the statement it is put in.
 *
 * The user is an enabled user of the realm, and either:
 *
 * - holds an active consent for the receiver's client (decided 2026-10-26);
 * - holds a live refresh token the receiver's client was issued (idem); or
 * - holds a live refresh token whose audience names the receiver as a
 *   resource server (decided 2026-10-31). A receiver is the resource server
 *   of the values its `oauth_clients.audience` lists, as the introspection
 *   endpoint reads that operator-set column, but never of a QAuth API
 *   audience (`urn:qauth:aud:`) nor of the realm's issuer, which names QAuth
 *   itself: an SSF receiver lists the issuer to manage its stream. A refresh
 *   token's audience is what the refresh grant gives its access tokens: its
 *   RFC 8707 `resource` when it has one, else its client's audience without
 *   the reserved values, else its client's `client_id`.
 *
 * A refresh token is live as the token endpoint reads it: neither revoked nor
 * expired, and its family not ended. The family ends at its start plus the
 * realm's `sso_max_lifespan`, and no later than the browser session that
 * started it; a realm that sets no limit (`null`; the realm refuses 0) bounds
 * neither (`refreshFamilyEnd` in the auth server).
 *
 * Access tokens are not stored, so one issued without a refresh token (no
 * stored consent) relates no one; nor does a consent's `resource_scopes`,
 * which records a grant, not a token.
 */
function relatedUserCondition(target: RelatedUserTarget, now: number): SQL {
  const { realmId, receiverClientId, userId } = target;
  return sql`(
    exists (
      select 1 from ${users}
      where ${users.id} = ${userId}
        and ${users.realmId} = ${realmId}
        and ${users.enabled}
    ) and (
      exists (
        select 1 from ${oauthConsents}
        where ${oauthConsents.realmId} = ${realmId}
          and ${oauthConsents.userId} = ${userId}
          and ${oauthConsents.oauthClientId} = ${receiverClientId}
          and ${oauthConsents.revokedAt} is null
      ) or exists (
        select 1 from ${refreshTokens}
        join ${realms} on ${realms.id} = ${realmId}
        join ${oauthClients} as "issuing_client"
          on "issuing_client"."id" = ${refreshTokens.oauthClientId}
        where ${refreshTokens.userId} = ${userId}
          and not ${refreshTokens.revoked}
          and ${refreshTokens.expiresAt} > ${now}
          and (
            ${realms.ssoMaxLifespan} is null
            or (
              ${refreshTokens.familyCreatedAt} + ${realms.ssoMaxLifespan} * 1000 > ${now}
              and (
                ${refreshTokens.familySessionExpiresAt} is null
                or ${refreshTokens.familySessionExpiresAt} > ${now}
              )
            )
          )
          and (
            ${refreshTokens.oauthClientId} = ${receiverClientId}
            or exists (
              select 1
              from jsonb_array_elements_text(
                case
                  when jsonb_array_length(${refreshTokens.resource}) > 0
                    then ${refreshTokens.resource}
                  when exists (
                    select 1
                    from jsonb_array_elements_text(
                      coalesce("issuing_client"."audience", '[]'::jsonb)
                    ) as "own"("value")
                    where "own"."value" !~* ${RESERVED_AUDIENCE_SQL_PATTERN}
                  ) then "issuing_client"."audience"
                  else jsonb_build_array("issuing_client"."client_id")
                end
              ) as "token_audience"("value")
              join ${oauthClients} as "receiver_client"
                on "receiver_client"."id" = ${receiverClientId}
              cross join lateral jsonb_array_elements_text(
                coalesce("receiver_client"."audience", '[]'::jsonb)
              ) as "served"("value")
              where "served"."value" = "token_audience"."value"
                and "served"."value" !~* ${RESERVED_AUDIENCE_SQL_PATTERN}
                and (
                  ${realms.issuer} is null
                  or "served"."value" not in (${realms.issuer}, ${realms.issuer} || '/')
                )
            )
          )
      )
    )
  )`;
}

/**
 * Factory for the Shared Signals Framework streams (issue #410). See
 * {@link SsfStreamsRepository} for the guarantees.
 *
 * @param db - The server's database. The delivery route's reads
 *   (`listDestinations`, `findForDelivery`, `hasSubject`) also run as the
 *   delivery role's user, which `eventDeliveryGrantStatements` lets read
 *   these tables.
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
      const related = relatedUserCondition(
        {
          realmId: sql`${realmId}`,
          receiverClientId: sql`${receiverClientId}`,
          userId: sql`${userId}`,
        },
        now
      );
      const { rows } = await db.execute<{ related: boolean }>(sql`select ${related} as "related"`);
      return rows[0]?.related === true;
    },

    async sweepUserSubjects(now) {
      // The user's id as the event store and the subject hold it, as a
      // `uuid`; any other text names no user, so its subject is unrelated.
      const userId = sql`(case when ${ssfStreamSubjects.eventSubjectId} ~* ${UUID_TEXT_SQL_PATTERN}
        then ${ssfStreamSubjects.eventSubjectId}::uuid end)`;
      const related = relatedUserCondition(
        {
          realmId: sql`${ssfStreams.realmId}`,
          receiverClientId: sql`${ssfStreams.receiverClientId}`,
          userId,
        },
        now
      );
      const result = await db.execute(sql`
        delete from ${ssfStreamSubjects}
        using ${ssfStreams}
        where ${ssfStreamSubjects.streamId} = ${ssfStreams.id}
          and ${ssfStreamSubjects.eventSubjectType} = 'user'
          and not ${related}
          -- Every event about the user is behind the realm's SSF fan-out
          -- position, so none of them can still be matched to this subject:
          -- the event of the withdrawal that ended the relation included.
          and not exists (
            select 1 from ${events}
            join ${eventDeliveryPositions}
              on ${eventDeliveryPositions.realmId} = ${events.realmId}
              and ${eventDeliveryPositions.destinationKind} = ${SSF_DELIVERY_KIND}
            where ${events.realmId} = ${ssfStreams.realmId}
              and ${events.subjectType} = 'user'
              and ${events.subjectId} = ${ssfStreamSubjects.eventSubjectId}
              and (${events.xid}, ${events.seq})
                > (${eventDeliveryPositions.xid}, ${eventDeliveryPositions.seq})
          )
          -- And none of them waits to be delivered to this stream: held,
          -- queued or retrying.
          and not exists (
            select 1 from ${eventDeliveries}
            join ${events} on ${events.id} = ${eventDeliveries.eventId}
            where ${eventDeliveries.destinationKind} = ${SSF_DELIVERY_KIND}
              and ${eventDeliveries.destinationId} = ${ssfStreams.id}::text
              and ${eventDeliveries.status} = 'pending'
              and ${events.subjectType} = 'user'
              and ${events.subjectId} = ${ssfStreamSubjects.eventSubjectId}
          )
      `);
      return result.rowCount ?? 0;
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

    async hasSubject(streamId, subject) {
      if (!isUuid(streamId)) return false;
      // Only the columns the delivery role may read (`EVENT_DELIVERY_COLUMNS`).
      const [row] = await db
        .select({ streamId: ssfStreamSubjects.streamId })
        .from(ssfStreamSubjects)
        .where(
          and(
            eq(ssfStreamSubjects.streamId, streamId),
            eq(ssfStreamSubjects.eventSubjectType, subject.type),
            eq(ssfStreamSubjects.eventSubjectId, subject.id)
          )
        )
        .limit(1);
      return row !== undefined;
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
