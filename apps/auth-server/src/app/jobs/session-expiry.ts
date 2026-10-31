import type { SessionService } from '@qauth-labs/fastify-plugin-sessions';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const SESSION_EXPIRY_JOB_NAME = 'session-expiry';

/**
 * Five minutes: how long, at most (plus the runner's wake window), a session
 * past its end can still read as live in its row and keep its clients in
 * the registry.
 */
export const SESSION_EXPIRY_INTERVAL_MS = 5 * 60_000;

/**
 * The role whose nodes run the job: `web`, which serves the browser sessions
 * and registers the session service.
 */
export const SESSION_EXPIRY_ROLE = 'web';

/** What {@link createSessionExpiryJob} takes. */
export interface SessionExpiryJobOptions {
  /** `fastify.sessionService`. */
  readonly sessions: Pick<SessionService, 'endLapsed'> | undefined;
}

/**
 * Mark the browser sessions past their end (ADR-019 Decision 3, issue #550).
 *
 * The session service treats a session past its absolute end or its realm's
 * idle limit as absent the moment it lapses, but its row still says live: the
 * clients it served stay in the registry, and back-channel logout and the
 * session events never hear of the end. This job marks those rows `expired`
 * or `idle`, so the revocation takes their registry rows and the service's
 * `onSessionsEnded` listeners hear of them, with the `system` actor.
 *
 * It works in batches of short transactions and stops between batches when
 * the run's signal aborts. Repeating it marks nothing new, so a run cut short
 * is finished by the next one. The deletion of old rows is the hourly
 * `session-purge` job, so a sweep that fails does not hold it up.
 *
 * Placed on the `web` role: its nodes register the session service, whose
 * cache the tombstones of the ended sessions go to.
 */
export function createSessionExpiryJob(options: SessionExpiryJobOptions): JobDefinition {
  const { sessions } = options;
  if (sessions === undefined || sessions === null) {
    throw new Error(
      'The session expiry job needs `fastify.sessionService`: register the session service plugin first'
    );
  }

  return defineJob({
    name: SESSION_EXPIRY_JOB_NAME,
    role: SESSION_EXPIRY_ROLE,
    intervalMs: SESSION_EXPIRY_INTERVAL_MS,
    async run({ signal, log }) {
      signal.throwIfAborted();
      const { ended } = await sessions.endLapsed({ signal });
      log.info({ ended }, 'lapsed sessions ended');
    },
  });
}
