import type { InferSelectModel } from 'drizzle-orm';

import type {
  SsfDeliveryMethod,
  ssfStreams,
  SsfStreamStatus,
  ssfStreamSubjects,
} from '../lib/schema/ssf';
import type { DbTransaction } from './database';

/** A stored Shared Signals Framework stream (issue #410). */
export type SsfStream = InferSelectModel<typeof ssfStreams>;

/** A subject a receiver added to its stream. */
export type SsfStreamSubject = InferSelectModel<typeof ssfStreamSubjects>;

/** Names one receiver's stream: the realm, the receiver's client row and the stream id. */
export interface SsfStreamKey {
  readonly realmId: string;
  /** The receiver's `oauth_clients.id`. */
  readonly receiverClientId: string;
  readonly streamId: string;
}

/** What a new stream is made of; the transmitter-supplied members included. */
export interface NewSsfStream {
  readonly realmId: string;
  readonly receiverClientId: string;
  readonly audience: string;
  readonly eventsRequested: readonly string[];
  readonly deliveryMethod: SsfDeliveryMethod;
  readonly endpointUrl: string;
  /** The `authorization_header`, already encrypted; `null` for none. */
  readonly authorizationHeader: string | null;
  readonly description: string | null;
  /** The stream id; the database makes one when absent. */
  readonly id?: string;
}

/** The receiver-supplied members an update sets; a member left out stays. */
export interface SsfStreamChanges {
  readonly eventsRequested?: readonly string[];
  readonly deliveryMethod?: SsfDeliveryMethod;
  readonly endpointUrl?: string;
  /** Encrypted; `null` removes it. */
  readonly authorizationHeader?: string | null;
  readonly description?: string | null;
}

/** A subject to add, in the form the table keeps. */
export interface NewSsfStreamSubject {
  readonly subjectKey: string;
  readonly subject: Readonly<Record<string, unknown>>;
  /** The event store subject it stands for, when QAuth can tell. */
  readonly eventSubject: { readonly type: string; readonly id: string } | null;
  readonly verified: boolean;
}

/** What {@link SsfStreamsRepository.addSubject} did; `missing` when the stream is gone. */
export type SsfAddSubjectResult = 'added' | 'present' | 'full' | 'missing';

/** A stream the delivery route serves, as it lists it for the fan-out. */
export interface SsfStreamDestination {
  readonly id: string;
  readonly realmId: string;
  readonly status: Extract<SsfStreamStatus, 'enabled' | 'paused'>;
  readonly eventsRequested: readonly string[];
  /** The event store subjects of its subjects; a subject QAuth cannot place is left out. */
  readonly subjects: ReadonlyArray<{ readonly type: string; readonly id: string }>;
}

/** A stream as one delivery attempt reads it. */
export interface SsfStreamForDelivery extends SsfStream {
  /**
   * Whether the stream may receive events at all: its realm's switch is on and
   * its receiver is enabled, not suspended and still holds the `ssf:stream`
   * scope. Its own `status` comes on top.
   */
  readonly active: boolean;
}

/** The deliveries of one stream, as its status endpoint reports them. */
export interface SsfStreamDeliveryStatus {
  /** Deliveries not finished yet: waiting for an attempt or a retry. */
  readonly pending: number;
  /** The stream's most recent failed attempt, if any. */
  readonly lastFailure?: {
    readonly eventId: string;
    /** The attempts made so far. */
    readonly attempts: number;
    /** The HTTP status the receiver answered; `null` when it did not answer. */
    readonly statusCode: number | null;
    /** A short class such as `http_status` or `timeout`. */
    readonly errorClass: string;
    /** When the attempt was recorded, in epoch milliseconds. */
    readonly at: number;
    /** `retrying`: another attempt comes; `failed`: the delivery gave up. */
    readonly state: 'retrying' | 'failed';
    /** When the next attempt is due, while `retrying`. */
    readonly nextAttemptAt?: number;
  };
}

/**
 * The streams of the Shared Signals Framework transmitter (issue #410).
 *
 * Every read and write a receiver makes names its realm and its client row,
 * so a receiver reaches only its own stream: another receiver's stream id
 * answers as if it did not exist. `listDestinations`, `findForDelivery` and
 * `deliveryStatus` serve the delivery route and the status endpoint.
 */
export interface SsfStreamsRepository {
  /** Create a stream. `null` when the receiver already has one in the realm. */
  create(stream: NewSsfStream): Promise<SsfStream | null>;
  /** The receiver's stream with this id, or `undefined`. */
  find(key: SsfStreamKey): Promise<SsfStream | undefined>;
  /** Every stream the receiver has in the realm: one at most. */
  list(realmId: string, receiverClientId: string): Promise<SsfStream[]>;
  /** Change the receiver-supplied members. `undefined` when there is no such stream. */
  update(key: SsfStreamKey, changes: SsfStreamChanges, now: number): Promise<SsfStream | undefined>;
  /** Delete the stream with its subjects. `false` when there is no such stream. */
  remove(key: SsfStreamKey): Promise<boolean>;
  /** Set the status and its reason. `undefined` when there is no such stream. */
  setStatus(
    key: SsfStreamKey,
    status: SsfStreamStatus,
    reason: string | null,
    now: number
  ): Promise<SsfStream | undefined>;
  /**
   * Add a subject. `present` when the stream has it already; `full` when the
   * stream holds `maxSubjects` and this one is new; `missing` when the stream
   * no longer exists, such as one its receiver deleted meanwhile.
   */
  addSubject(
    streamId: string,
    subject: NewSsfStreamSubject,
    maxSubjects: number
  ): Promise<SsfAddSubjectResult>;
  /** Remove a subject by its canonical key. `false` when the stream did not have it. */
  removeSubject(streamId: string, subjectKey: string): Promise<boolean>;
  /** The subjects of a stream, oldest first. */
  listSubjects(streamId: string): Promise<SsfStreamSubject[]>;
  /**
   * Every stream the delivery route serves: `enabled` and `paused` ones of an
   * active receiver (enabled, not suspended, holding `ssf:stream`), in realms
   * whose switch is on.
   */
  listDestinations(): Promise<SsfStreamDestination[]>;
  /** One stream for a delivery attempt, whatever its status, or `undefined`. */
  findForDelivery(streamId: string): Promise<SsfStreamForDelivery | undefined>;
  /**
   * The stream's pending deliveries and its latest failed attempt. A row an
   * attempt is running on at `now` (epoch milliseconds) is left out of the
   * latest failure until its outcome is recorded.
   */
  deliveryStatus(streamId: string, now: number): Promise<SsfStreamDeliveryStatus>;
  /**
   * Write the delivery of an event addressed to one stream, such as its
   * verification event, in the transaction that wrote the event: it then
   * reaches that stream and no other, and it cannot be missed by a fan-out
   * that started before the stream existed.
   *
   * @returns `false` when the transaction wrote no such event
   */
  enqueueForEvent(
    tx: DbTransaction,
    request: { readonly streamId: string; readonly eventId: string; readonly now: number }
  ): Promise<boolean>;
}
