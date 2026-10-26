import {
  DEFAULT_EVENT_RETENTION_POLICY,
  type EventRetentionPolicy,
} from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';

import { createEventRetentionJob, type RetentionRoute } from './event-retention';
import type { JobDefinition } from './job-runner';
import { createPurgeExpiredJob } from './purge-expired';

export * from './advisory-lock';
export * from './event-retention';
export * from './job-runner';
export * from './purge-expired';

/** What the server's jobs need beside the Fastify instance. */
export interface ServerJobSettings {
  /** The delivery routes (#460): event retention reads their enabled destinations. */
  readonly deliveryRoutes?: readonly RetentionRoute[];
  /**
   * Route kinds no node serves, such as `ssf` while its switch is off: they
   * hold no event back from retention.
   */
  readonly unservedDeliveryKinds?: readonly string[];
  /**
   * The event retention of a realm whose row is gone (#536): the seeds a new
   * realm gets. Defaults to 90 days of user events and 365 of admin events.
   */
  readonly eventRetentionFallback?: EventRetentionPolicy;
}

/**
 * Every job the auth server defines. The job runner starts those whose role
 * this node holds.
 */
export function serverJobs(
  fastify: FastifyInstance,
  settings: ServerJobSettings = {}
): JobDefinition[] {
  return [
    createPurgeExpiredJob(fastify.repositories),
    createEventRetentionJob({
      retention: fastify.repositories.eventRetention,
      routes: settings.deliveryRoutes ?? [],
      unservedKinds: settings.unservedDeliveryKinds ?? [],
      fallback: settings.eventRetentionFallback ?? DEFAULT_EVENT_RETENTION_POLICY,
      deleted: fastify.metrics.eventsRetentionDeleted,
    }),
  ];
}
