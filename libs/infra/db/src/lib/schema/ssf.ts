import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  jsonb,
  pgTable,
  primaryKey,
  text,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { oauthClients, realms } from './core';
import { EPOCH_MS_NOW, JSONB_EMPTY_ARRAY } from './sql-helpers';

/**
 * Where a Shared Signals Framework stream stands (SSF 1.0 §8.1.2): the values
 * `ssf_streams.status` accepts. The CHECK `ssf_streams_status_known` is built
 * from this list.
 *
 * - `enabled` — QAuth sends the stream's events.
 * - `paused` — QAuth sends nothing, and holds the events for the stream until
 *   it is enabled again or their attempts run out.
 * - `disabled` — QAuth sends nothing and holds nothing.
 */
export const SSF_STREAM_STATUSES = ['enabled', 'paused', 'disabled'] as const;

export type SsfStreamStatus = (typeof SSF_STREAM_STATUSES)[number];

/**
 * The delivery methods a stream may use. Push (RFC 8935) only: poll (RFC
 * 8936) is a later issue.
 */
export const SSF_DELIVERY_METHODS = ['urn:ietf:rfc:8935'] as const;

export type SsfDeliveryMethod = (typeof SSF_DELIVERY_METHODS)[number];

const inList = (values: readonly string[]) =>
  sql.raw(values.map((value) => `'${value}'`).join(', '));

/**
 * The streams of the Shared Signals Framework transmitter (SSF 1.0 §8, issue
 * #410): one row per receiver and realm.
 *
 * A receiver is an OAuth client of the realm, and it has at most one stream
 * there: a second create is answered `409`, as SSF 1.0 §8.1.1.1 provides for
 * a transmitter that keeps one stream per receiver. Deleting the client or the
 * realm deletes its stream.
 *
 * `audience` is the SETs' `aud`, the receiver's `client_id` when the stream
 * was created; SSF does not let it change. `authorization_header` is the value
 * the receiver asked QAuth to send with every push, encrypted with the realm's
 * `data_at_rest` key (`v1.<kid>.<iv>.<ciphertext>`), never in the clear.
 */
export const ssfStreams = pgTable(
  'ssf_streams',
  {
    /** The `stream_id`. */
    id: uuid('id')
      .primaryKey()
      .default(sql`uuidv7()`),
    realmId: uuid('realm_id')
      .notNull()
      .references(() => realms.id, { onDelete: 'cascade' }),
    /** The receiver: the OAuth client that created the stream. */
    receiverClientId: uuid('receiver_client_id')
      .notNull()
      .references(() => oauthClients.id, { onDelete: 'cascade' }),
    /** The SETs' `aud`: the receiver's `client_id`. */
    audience: varchar('audience', { length: 255 }).notNull(),
    /** `events_requested`: the event type URIs the receiver asked for. */
    eventsRequested: jsonb('events_requested')
      .$type<string[]>()
      .notNull()
      .default(JSONB_EMPTY_ARRAY),
    /** `delivery.method`. */
    deliveryMethod: varchar('delivery_method', { length: 64 }).$type<SsfDeliveryMethod>().notNull(),
    /** `delivery.endpoint_url`: where push delivery POSTs each SET. */
    endpointUrl: varchar('endpoint_url', { length: 2048 }).notNull(),
    /** `delivery.authorization_header`, encrypted; `null` when the receiver set none. */
    authorizationHeader: text('authorization_header'),
    /** `description`, cut to 1024 characters. */
    description: varchar('description', { length: 1024 }),
    status: varchar('status', { length: 16 }).$type<SsfStreamStatus>().notNull().default('enabled'),
    /** The `reason` given with the last status change, if any. */
    statusReason: varchar('status_reason', { length: 255 }),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
    updatedAt: bigint('updated_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    unique('ssf_streams_receiver_unique').on(t.realmId, t.receiverClientId),
    check('ssf_streams_status_known', sql`${t.status} in (${inList(SSF_STREAM_STATUSES)})`),
    check(
      'ssf_streams_delivery_method_known',
      sql`${t.deliveryMethod} in (${inList(SSF_DELIVERY_METHODS)})`
    ),
    check('ssf_streams_audience_not_empty', sql`${t.audience} <> ''`),
    check('ssf_streams_endpoint_url_not_empty', sql`${t.endpointUrl} <> ''`),
    check(
      'ssf_streams_events_requested_is_array',
      sql`jsonb_typeof(${t.eventsRequested}) = 'array'`
    ),
  ]
);

/**
 * The subjects a receiver added to its stream (SSF 1.0 §8.1.3). The
 * transmitter's `default_subjects` is `NONE`: a stream receives events only
 * about the subjects listed here, and the verification events about itself.
 *
 * `subject` is the RFC 9493 subject identifier as the receiver sent it, and
 * `subject_key` its canonical form, which makes a subject added twice one
 * row. `event_subject_type` and `event_subject_id` name the event store's
 * subject the identifier stands for, when QAuth can tell (a user of the realm
 * as `iss_sub`, a client by its `client_id`); a subject QAuth cannot place is
 * kept and matches no event.
 */
export const ssfStreamSubjects = pgTable(
  'ssf_stream_subjects',
  {
    streamId: uuid('stream_id')
      .notNull()
      .references(() => ssfStreams.id, { onDelete: 'cascade' }),
    /** The canonical JSON of `subject`: keys sorted, no white space. */
    subjectKey: varchar('subject_key', { length: 2048 }).notNull(),
    /** The subject identifier, as the receiver sent it. */
    subject: jsonb('subject').$type<Record<string, unknown>>().notNull(),
    /** The event store subject's `type` it stands for; `null` when none. */
    eventSubjectType: varchar('event_subject_type', { length: 32 }),
    /** The event store subject's `id` it stands for; `null` when none. */
    eventSubjectId: varchar('event_subject_id', { length: 255 }),
    /** `verified`: whether the receiver verified the subject; true when it did not say. */
    verified: boolean('verified').notNull().default(true),
    createdAt: bigint('created_at', { mode: 'number' }).notNull().default(EPOCH_MS_NOW),
  },
  (t) => [
    primaryKey({ columns: [t.streamId, t.subjectKey], name: 'ssf_stream_subjects_pk' }),
    check(
      'ssf_stream_subjects_event_subject_complete',
      sql`(${t.eventSubjectType} is null) = (${t.eventSubjectId} is null)`
    ),
    check('ssf_stream_subjects_subject_is_object', sql`jsonb_typeof(${t.subject}) = 'object'`),
  ]
);
