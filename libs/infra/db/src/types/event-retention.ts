import type { EventCategory } from '@qauth-labs/shared-events';
import type { EventRetentionPolicy } from '@qauth-labs/shared-validation';

import type { EventPosition } from '../lib/events/position';
import type { OfferedDestinations } from './event-deliveries';
import type { EventChainBreakReason, EventChainPoint } from './repository';

/** A realm that has events, with the retention that applies to them (issue #536). */
export interface RealmEventRetention extends EventRetentionPolicy {
  readonly realmId: string;
  /**
   * `false` when the realm row no longer exists: an event outlives its realm,
   * and the fallback policy the caller passed applies to its events.
   */
  readonly realmExists: boolean;
}

/** What {@link EventRetentionRepository.deleteBatch} takes. */
export interface EventRetentionBatchRequest {
  readonly realmId: string;
  readonly category: EventCategory;
  /** Delete only events written before this time, in epoch milliseconds. */
  readonly before: number;
  /**
   * Delete only events at or before this position of the realm's stream:
   * what {@link EventRetentionRepository.offeredThrough} answered.
   */
  readonly through: EventPosition;
  /** The most rows the batch deletes, 1 to 10000. */
  readonly limit: number;
  /** The caller's clock, in epoch milliseconds: the anchor's `updated_at`. */
  readonly now: number;
}

/** An admin row the batch did not delete because the chain breaks at it. */
export interface EventRetentionChainBreak {
  readonly id: string;
  readonly seq: bigint;
  readonly reason: EventChainBreakReason;
}

/** What one {@link EventRetentionRepository.deleteBatch} did. */
export type EventRetentionBatch =
  /** Another job instance holds the realm's retention lock; nothing was done. */
  | { readonly status: 'busy' }
  | {
      readonly status: 'done';
      /** Rows deleted. */
      readonly deleted: number;
      /** The batch was full: more rows may be deletable now. */
      readonly more: boolean;
      /** The realm's new chain anchor, when the batch deleted chained admin rows. */
      readonly anchor: EventChainPoint | null;
      /**
       * The oldest admin row left, when the chain breaks at it. The batch
       * deletes no admin row from there on, so the break stays for
       * `verifyChain` to report.
       */
      readonly chainBreak: EventRetentionChainBreak | null;
    };

/** The time of each category's oldest event, in epoch milliseconds; `null` when none. */
export type OldestEventTimes = Readonly<Record<EventCategory, number | null>>;

/**
 * The retention job's access to the event store (ADR-020 §3, ADR-019
 * Decision 7, issue #536).
 *
 * A row is deletable when it is older than its realm's retention for its
 * category and every enabled delivery destination has finished it
 * ({@link offeredThrough}). Cursor readers are not tracked: a reader that
 * falls behind retention gets `cursor_expired` from the event API.
 *
 * Batches delete the oldest rows first. A realm's admin rows are deleted only
 * from the start of its chain, in `seq` order, never its head, and only while
 * each row verifies against the one before it; the last one deleted becomes
 * the realm's anchor in `event_chain_anchors`, in the batch's transaction,
 * so `verifyChain` still verifies from there.
 *
 * Each batch is one short transaction that holds the realm's retention lock
 * (`pg_try_advisory_xact_lock`), so two job instances at once never delete
 * from one realm together: the second gets `busy`, and each row is deleted
 * once. A short transaction also keeps the event store's read horizon moving.
 *
 * It needs the grants of `eventRetentionGrantStatements`, the only role that
 * may delete from `events`.
 */
export interface EventRetentionRepository {
  /**
   * Every realm that has events, the realms whose row is gone included, with
   * its retention: the realm row's, or `fallback` for a realm that no longer
   * exists.
   */
  realms(fallback: EventRetentionPolicy): Promise<RealmEventRetention[]>;

  /**
   * The latest position of the realm's stream that every enabled destination
   * has finished (delivered or failed). With `served`, a disabled destination
   * of a listed route kind does not hold events back; a kind not listed
   * counts in full.
   *
   * @throws {TypeError} on a realm id that is not a UUID
   */
  offeredThrough(realmId: string, served?: OfferedDestinations): Promise<EventPosition>;

  /**
   * Delete one batch of a realm's oldest rows of one category that are older
   * than `before` and at or before `through`.
   *
   * @throws {TypeError} on a malformed request, or a position of another realm
   */
  deleteBatch(request: EventRetentionBatchRequest): Promise<EventRetentionBatch>;

  /** When each category's oldest event was written, over every realm. */
  oldestEventTimes(): Promise<OldestEventTimes>;
}
