import type { EventCategory, EventEnvelope } from '@qauth-labs/shared-events';
import type { InferSelectModel } from 'drizzle-orm';

import type { EventPosition } from '../lib/events/position';
import type { eventDeliveries } from '../lib/schema/event-deliveries';

/** A stored delivery: one destination's row for one event (issue #460). */
export type EventDelivery = InferSelectModel<typeof eventDeliveries>;

/**
 * A place events are delivered to, as a route lists it for the fan-out
 * (ADR-019 Decision 8, issue #460).
 */
export interface EventDeliveryDestination {
  /** The route that delivers to it: the route's `kind`, such as `webhook`. */
  readonly kind: string;
  /** Its id within the route, such as a webhook subscription's id. */
  readonly id: string;
  /** The realm whose events it receives. */
  readonly realmId: string;
  /** Only events of these types. Absent: every type. An empty list matches none. */
  readonly types?: readonly string[];
  /** Only events of these categories. Absent: both. An empty list matches none. */
  readonly categories?: readonly EventCategory[];
  /**
   * Only events about one of these subjects (`subject.type` and
   * `subject.id`). Absent: any subject, or none. An empty list matches none,
   * and an event without a subject never matches a list.
   */
  readonly subjects?: ReadonlyArray<{ readonly type: string; readonly id: string }>;
}

/**
 * The destinations a caller knows to be enabled, so that a disabled one does
 * not hold back the retention job (#536): each route kind the caller lists,
 * and every enabled destination of those kinds, as the routes list them for
 * the fan-out.
 */
export interface OfferedDestinations {
  /**
   * The route kinds whose destinations were listed. A kind left out counts
   * in full: each of its pending deliveries and its position hold events
   * back.
   */
  readonly kinds: readonly string[];
  /** Every enabled destination of those kinds, of any realm. */
  readonly destinations: readonly Pick<EventDeliveryDestination, 'kind' | 'id' | 'realmId'>[];
}

/** What {@link EventDeliveriesRepository.fanOut} takes. */
export interface EventFanOutRequest {
  /**
   * The route kinds the calling node serves. Only their positions are read,
   * moved and forgotten, so a node that serves fewer kinds than another, as
   * during a rollout, leaves the other kinds alone. Empty: nothing is done.
   */
  readonly kinds: readonly string[];
  /**
   * Every enabled destination of those kinds. A realm with no destination of
   * a kind has nothing fanned out for it, and its position for that kind is
   * forgotten.
   *
   * A destination of a kind not in `kinds` is refused.
   */
  readonly destinations: readonly EventDeliveryDestination[];
  /** The worker's clock, in epoch milliseconds. */
  readonly now: number;
  /** Events read per page of one realm. Defaults to 500; at most 1000. */
  readonly pageSize?: number;
  /** Pages read per realm in one call, so one busy realm cannot hold the rest. Defaults to 10. */
  readonly maxPagesPerRealm?: number;
}

/** What one {@link EventDeliveriesRepository.fanOut} did. */
export interface EventFanOutResult {
  /** Streams read: one per realm and route kind. */
  readonly realms: number;
  /** Streams another worker was fanning out, left to it. */
  readonly skippedRealms: number;
  /** Events read. */
  readonly events: number;
  /** Delivery rows written. */
  readonly deliveries: number;
  /** Whether a stream still had events when it reached `maxPagesPerRealm`. */
  readonly more: boolean;
}

/** A destination with at least one delivery due. */
export interface DueEventDestination {
  readonly kind: string;
  readonly id: string;
}

/** How many due rows of one destination a claim takes at most. */
export interface EventDeliveryPick extends DueEventDestination {
  readonly limit: number;
}

/** What {@link EventDeliveriesRepository.claim} takes. */
export interface EventDeliveryClaimRequest {
  readonly picks: readonly EventDeliveryPick[];
  /** The worker's clock, in epoch milliseconds. */
  readonly now: number;
  /** How long the claim holds a row, in milliseconds. */
  readonly leaseMs: number;
  /**
   * The attempts a delivery gets. A due row that has used them all, because
   * its last attempt was interrupted, ends `failed` instead of being claimed.
   */
  readonly maxAttempts: number;
}

/** The part of a claim that names it: the row and the attempt it made. */
export interface EventDeliveryClaimRef {
  readonly id: string;
  /** The attempt the claim made, 1 for the first. */
  readonly attempt: number;
}

/** A claimed delivery and the event it delivers. */
export interface ClaimedEventDelivery extends EventDeliveryClaimRef {
  readonly destinationKind: string;
  readonly destinationId: string;
  readonly realmId: string;
  readonly eventId: string;
  /** When the claim's lease runs out, in epoch milliseconds. */
  readonly lockedUntil: number;
  /** The event, or `null` when it is stored in a layout this release cannot read. */
  readonly event: EventEnvelope | null;
}

/** How an attempt ended, as {@link EventDeliveriesRepository.record} stores it. */
export type EventDeliveryAttemptRecord =
  | { readonly result: 'delivered'; readonly statusCode?: number }
  | {
      readonly result: 'retry';
      /** When the next attempt is due, in epoch milliseconds. */
      readonly nextAttemptAt: number;
      readonly statusCode?: number;
      readonly errorClass: string;
    }
  | { readonly result: 'failed'; readonly statusCode?: number; readonly errorClass: string };

/**
 * The delivery queue of the delivery role (ADR-019 Decision 8, issue #460).
 *
 * Every event reaches every matching destination at least once:
 *
 * - The fan-out reads each realm's stream from its position, below the safe
 *   read horizon of the event store (#457), and writes one row per matching
 *   destination and event in the transaction that moves the position. A
 *   crash before the commit writes nothing and moves nothing.
 * - A claim leases rows. A worker that dies leaves its rows to come due again
 *   when the lease runs out.
 * - An outcome is written only by the claim that made the attempt: a worker
 *   whose lease ran out and whose row was claimed again writes nothing.
 *
 * All times are the worker's clock, in epoch milliseconds.
 */
export interface EventDeliveriesRepository {
  /**
   * Write the delivery rows for the events after each position, one per
   * realm and route kind, and move the positions on. A stream another worker
   * is fanning out is skipped (`pg_try_advisory_xact_lock`), so one node does
   * each at a time. A stream seen for the first time starts at the horizon: a
   * new destination receives the events committed from then on, not the
   * realm's history.
   *
   * @throws {TypeError} on a destination of a kind the request does not serve
   */
  fanOut(request: EventFanOutRequest): Promise<EventFanOutResult>;

  /** The destinations of these kinds with at least one delivery due at `now`. */
  dueDestinations(kinds: readonly string[], now: number): Promise<DueEventDestination[]>;

  /**
   * Claim due rows, earliest due first within each destination, skipping the
   * rows another claim holds (`FOR UPDATE SKIP LOCKED`). Each claim counts
   * an attempt and leases the row until `now + leaseMs`. A row whose event is
   * stored in a layout this release cannot read is left to a node that can.
   */
  claim(request: EventDeliveryClaimRequest): Promise<ClaimedEventDelivery[]>;

  /**
   * Store how a claimed attempt ended.
   *
   * @returns `false` when the claim no longer holds the row (its lease ran
   *   out and another claim took it, or it was released): nothing is written.
   */
  record(
    claim: EventDeliveryClaimRef,
    outcome: EventDeliveryAttemptRecord,
    now: number
  ): Promise<boolean>;

  /**
   * Give claimed rows back before their lease ends, so another worker can
   * take them at once. The attempt still counts: it may have reached the
   * destination.
   *
   * @returns how many rows were given back
   */
  release(claims: readonly EventDeliveryClaimRef[], now: number): Promise<number>;

  /**
   * The lowest position of a realm's stream that every destination has
   * finished: every event at or before it has been delivered, or has failed
   * for good, to every destination it matched, and no later fan-out writes a
   * row for it. The retention job (#536) deletes only events at or before it.
   *
   * @throws {TypeError} on a realm id that is not a UUID
   */
  minOffered(realmId: string): Promise<EventPosition>;

  /** The deliveries not finished yet, by route kind. */
  pendingByKind(): Promise<Record<string, number>>;

  /**
   * Seconds since the oldest event that waits for a delivery was written: an
   * event with an unfinished delivery, or one the fan-out has not read yet.
   * 0 when none waits.
   */
  deliveryLagSeconds(now: number): Promise<number>;

  /** Every delivery of one event, oldest first. */
  listForEvent(eventId: string): Promise<EventDelivery[]>;
}
