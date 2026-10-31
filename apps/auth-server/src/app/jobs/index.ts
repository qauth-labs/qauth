import type { RepositoryName } from '@qauth-labs/fastify-plugin-db';
import {
  DEFAULT_EVENT_RETENTION_POLICY,
  type EventRetentionPolicy,
} from '@qauth-labs/shared-validation';
import type { FastifyInstance } from 'fastify';

import {
  createEventRetentionJob,
  EVENT_RETENTION_JOB_NAME,
  EVENT_RETENTION_ROLE,
  type RetentionRoute,
} from './event-retention';
import {
  createInteractionExpiryJob,
  INTERACTION_EXPIRY_JOB_NAME,
  INTERACTION_EXPIRY_ROLE,
} from './interaction-expiry';
import { type JobDefinition, SERVICE_ROLES, type ServiceRole } from './job-runner';
import {
  createPurgeExpiredJob,
  PURGE_EXPIRED_JOB_NAME,
  PURGE_EXPIRED_REPOSITORIES,
  PURGE_EXPIRED_ROLE,
} from './purge-expired';
import {
  createSessionPurgeJob,
  DEFAULT_SESSION_RETENTION_DAYS,
  SESSION_PURGE_JOB_NAME,
  SESSION_PURGE_ROLE,
} from './session-purge';
import {
  createSsfSubjectSweepJob,
  SSF_SUBJECT_SWEEP_JOB_NAME,
  SSF_SUBJECT_SWEEP_ROLE,
} from './ssf-subject-sweep';

export * from './advisory-lock';
export * from './event-retention';
export * from './interaction-expiry';
export * from './job-runner';
export * from './purge-expired';
export * from './session-purge';
export * from './ssf-subject-sweep';

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
  /**
   * `SESSION_RETENTION_DAYS` (#550): how long the session purge keeps an
   * ended session's row. Defaults to 30.
   */
  readonly sessionRetentionDays?: number;
}

/**
 * Where one of the server's jobs runs (ADR-019 Decision 8, #495): its role,
 * the repositories it reads and writes, and how to build it. A process builds
 * only the jobs of its roles, so it never builds a job over a repository it
 * does not load.
 *
 * The key jobs (rotation, #542) go on `signer` when they land.
 */
export interface ServerJobPlacement {
  readonly name: string;
  readonly role: ServiceRole;
  readonly repositories: readonly RepositoryName[];
  create(fastify: FastifyInstance, settings: ServerJobSettings): JobDefinition;
}

/** Every job the auth server defines, with its role. */
export const SERVER_JOBS: readonly ServerJobPlacement[] = [
  {
    name: PURGE_EXPIRED_JOB_NAME,
    role: PURGE_EXPIRED_ROLE,
    repositories: PURGE_EXPIRED_REPOSITORIES,
    create: (fastify) => createPurgeExpiredJob(fastify.repositories),
  },
  {
    name: EVENT_RETENTION_JOB_NAME,
    role: EVENT_RETENTION_ROLE,
    repositories: ['eventRetention'],
    create: (fastify, settings) =>
      createEventRetentionJob({
        retention: fastify.repositories.eventRetention,
        routes: settings.deliveryRoutes ?? [],
        unservedKinds: settings.unservedDeliveryKinds ?? [],
        fallback: settings.eventRetentionFallback ?? DEFAULT_EVENT_RETENTION_POLICY,
        deleted: fastify.metrics.eventsRetentionDeleted,
      }),
  },
  {
    // The SSF user subjects whose relation has ended (#540).
    name: SSF_SUBJECT_SWEEP_JOB_NAME,
    role: SSF_SUBJECT_SWEEP_ROLE,
    repositories: ['ssfStreams'],
    create: (fastify) => createSsfSubjectSweepJob(fastify.repositories),
  },
  {
    // The Interaction API's expired interactions (#592): audited and cleared.
    name: INTERACTION_EXPIRY_JOB_NAME,
    role: INTERACTION_EXPIRY_ROLE,
    repositories: ['events'],
    create: (fastify) =>
      createInteractionExpiryJob({ redis: fastify.redis, events: fastify.repositories.events }),
  },
  {
    // Ends the sessions past an end and deletes old ended rows (#550),
    // through the session service, which reads `sessions` and `realms`.
    name: SESSION_PURGE_JOB_NAME,
    role: SESSION_PURGE_ROLE,
    repositories: [],
    create: (fastify, settings) =>
      createSessionPurgeJob({
        sessions: fastify.sessionService,
        retentionDays: settings.sessionRetentionDays ?? DEFAULT_SESSION_RETENTION_DAYS,
      }),
  },
];

/**
 * The jobs of `roles`, built. The job runner starts those whose role this node
 * holds; building only those keeps a job's repositories out of a process that
 * does not run it.
 *
 * @param roles - the roles this process holds; every role by default
 */
export function serverJobs(
  fastify: FastifyInstance,
  settings: ServerJobSettings = {},
  roles: readonly ServiceRole[] = SERVICE_ROLES
): JobDefinition[] {
  return SERVER_JOBS.filter((job) => roles.includes(job.role)).map((job) =>
    job.create(fastify, settings)
  );
}
