import type { DeliveryRoute } from '@qauth-labs/fastify-plugin-event-delivery';
import { DAY_MS, type EventRetentionPolicy } from '@qauth-labs/shared-validation';
import type { FastifyBaseLogger, FastifyInstance } from 'fastify';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const EVENT_RETENTION_JOB_NAME = 'event-retention';

/** One hour. */
export const EVENT_RETENTION_INTERVAL_MS = 60 * 60_000;

/** The rows one batch deletes at most: one short transaction each. */
export const EVENT_RETENTION_BATCH_SIZE = 1000;

/** The retention job's access to the event store. */
export type EventRetentionStore = Pick<
  FastifyInstance['repositories']['eventRetention'],
  'realms' | 'offeredThrough' | 'deleteBatch'
>;

/** The destinations the job knows to be enabled: what `offeredThrough` takes. */
type OfferedDestinations = NonNullable<Parameters<EventRetentionStore['offeredThrough']>[1]>;

/** The part of a delivery route the job reads: its kind and its enabled destinations. */
export type RetentionRoute = Pick<DeliveryRoute, 'kind' | 'destinations'>;

/** Rows deleted, by event category (`qauth_events_retention_deleted_total`). */
export interface EventRetentionDeletedCounter {
  inc(labels: { category: 'user' | 'admin' }, value: number): void;
}

/** What {@link createEventRetentionJob} takes. */
export interface EventRetentionJobOptions {
  readonly retention: EventRetentionStore;
  /**
   * The delivery routes of this node, the delivery role's own. Their enabled
   * destinations decide which deliveries hold events back: a disabled one
   * does not. Without routes, every pending delivery holds its event.
   */
  readonly routes: readonly RetentionRoute[];
  /**
   * The retention of a realm whose row no longer exists: an event outlives
   * its realm. The auth server passes the seeds a new realm would get.
   */
  readonly fallback: EventRetentionPolicy;
  readonly deleted?: EventRetentionDeletedCounter;
  /** Defaults to {@link EVENT_RETENTION_BATCH_SIZE}. */
  readonly batchSize?: number;
}

/** Whether a listed destination has the fields the offered rule reads. */
function wellFormed(value: unknown): value is { kind?: unknown; id: string; realmId: string } {
  const destination = value as { id?: unknown; realmId?: unknown } | null;
  return (
    typeof destination === 'object' &&
    destination !== null &&
    typeof destination.id === 'string' &&
    typeof destination.realmId === 'string'
  );
}

/**
 * Ask each route for its enabled destinations. A route whose listing fails,
 * or lists something malformed, is left out: its kind then counts in full,
 * so a listing that failed never lets an event go ahead of a destination.
 */
async function listServed(
  routes: readonly RetentionRoute[],
  log: FastifyBaseLogger
): Promise<OfferedDestinations> {
  const kinds: string[] = [];
  const destinations: Array<{ kind: string; id: string; realmId: string }> = [];
  for (const route of routes) {
    let listed: readonly unknown[];
    try {
      listed = await route.destinations();
    } catch (error) {
      log.warn(
        { err: error, kind: route.kind },
        'a delivery route could not list its destinations; all its deliveries hold events back this run'
      );
      continue;
    }
    if (!Array.isArray(listed) || !listed.every(wellFormed)) {
      log.warn(
        { kind: route.kind },
        'a delivery route listed a malformed destination; all its deliveries hold events back this run'
      );
      continue;
    }
    kinds.push(route.kind);
    for (const destination of listed) {
      destinations.push({ kind: route.kind, id: destination.id, realmId: destination.realmId });
    }
  }
  return { kinds, destinations };
}

/**
 * Event retention (ADR-020 §3, ADR-019 Decision 7, issue #536): delete each
 * realm's events once they are older than the realm's retention and every
 * enabled delivery destination has finished them.
 *
 * For each realm that has events, the job reads the latest position every
 * enabled destination has finished, then deletes in batches, oldest first:
 * user events past `user_event_retention_days`, admin events past
 * `admin_event_retention_days`. Admin events go only from the start of the
 * realm's chain, never its head, and the repository stores the last one
 * deleted as the chain's anchor in the batch's transaction. A realm another
 * instance holds is left to it. Cursor readers are not tracked.
 *
 * A chain break at the oldest admin event stops the admin deletions of that
 * realm and is logged as an error: the rows stay for `verifyChain` and the
 * operator. Repeating the job deletes nothing new, so a run cut short at its
 * time limit is finished by the next one.
 *
 * Placed on the `delivery` role: its nodes have the delivery routes, so a
 * disabled destination does not hold events back, and they serve no
 * inbound request.
 */
export function createEventRetentionJob(options: EventRetentionJobOptions): JobDefinition {
  const batchSize = options.batchSize ?? EVENT_RETENTION_BATCH_SIZE;

  return defineJob({
    name: EVENT_RETENTION_JOB_NAME,
    role: 'delivery',
    intervalMs: EVENT_RETENTION_INTERVAL_MS,
    async run({ signal, now, log }) {
      const served = await listServed(options.routes, log);
      const realms = await options.retention.realms(options.fallback);
      const deleted = { user: 0, admin: 0 };
      let busyRealms = 0;

      for (const realm of realms) {
        signal.throwIfAborted();
        const through = await options.retention.offeredThrough(realm.realmId, served);
        realmLoop: for (const [category, days] of [
          ['user', realm.userEventRetentionDays],
          ['admin', realm.adminEventRetentionDays],
        ] as const) {
          for (;;) {
            signal.throwIfAborted();
            const batch = await options.retention.deleteBatch({
              realmId: realm.realmId,
              category,
              before: now() - days * DAY_MS,
              through,
              limit: batchSize,
              now: now(),
            });
            if (batch.status === 'busy') {
              busyRealms += 1;
              break realmLoop;
            }
            deleted[category] += batch.deleted;
            if (batch.deleted > 0) options.deleted?.inc({ category }, batch.deleted);
            if (batch.chainBreak) {
              log.error(
                {
                  realm: realm.realmId,
                  eventId: batch.chainBreak.id,
                  seq: batch.chainBreak.seq.toString(),
                  reason: batch.chainBreak.reason,
                },
                'the admin event chain breaks at its oldest event; retention keeps it and every later admin event'
              );
            }
            if (!batch.more) break;
          }
        }
      }
      log.info({ deleted, realms: realms.length, busyRealms }, 'event retention ran');
    },
  });
}
