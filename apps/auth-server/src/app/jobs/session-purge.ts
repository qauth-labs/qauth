import type { SessionService } from '@qauth-labs/fastify-plugin-sessions';
import { DAY_MS } from '@qauth-labs/shared-validation';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const SESSION_PURGE_JOB_NAME = 'session-purge';

/** One hour. */
export const SESSION_PURGE_INTERVAL_MS = 60 * 60_000;

/**
 * The role whose nodes run the job: `web`, which serves the browser sessions
 * and registers the session service.
 */
export const SESSION_PURGE_ROLE = 'web';

/** `SESSION_RETENTION_DAYS`'s default. */
export const DEFAULT_SESSION_RETENTION_DAYS = 30;

/** What {@link createSessionPurgeJob} takes. */
export interface SessionPurgeJobOptions {
  /** `fastify.sessionService`. */
  readonly sessions: Pick<SessionService, 'endLapsed' | 'purge'>;
  /** `SESSION_RETENTION_DAYS`: how long an ended session's row is kept. */
  readonly retentionDays: number;
}

/**
 * The browser session purge (ADR-019 Decision 3, issue #550).
 *
 * Each run first ends, in Postgres, the sessions past their absolute end or
 * their realm's idle limit: the session service already treats them as
 * absent, but their rows still said live, so the clients they served stayed
 * in the registry and back-channel logout never heard of the end. They are
 * marked `expired` or `idle`, at the time each ended, and the service's
 * `onSessionsEnded` listeners hear of them with the `system` actor.
 *
 * It then deletes the rows that ended, or passed their stored `expires_at`,
 * more than `SESSION_RETENTION_DAYS` ago: until then the account and admin
 * session lists show them as ended. A live session is never deleted.
 *
 * Both steps work in batches of short transactions and stop between batches
 * when the run's signal aborts. Repeating the job ends and deletes nothing
 * new, so a run cut short is finished by the next one.
 *
 * Placed on the `web` role: its nodes register the session service, whose
 * cache the tombstones of the ended sessions go to.
 */
export function createSessionPurgeJob(options: SessionPurgeJobOptions): JobDefinition {
  const { sessions, retentionDays } = options;
  if (sessions === undefined || sessions === null) {
    throw new Error(
      'The session purge job needs `fastify.sessionService`: register the session service plugin first'
    );
  }
  if (!Number.isInteger(retentionDays) || retentionDays < 1) {
    throw new RangeError(`SESSION_RETENTION_DAYS must be a positive integer, got ${retentionDays}`);
  }

  return defineJob({
    name: SESSION_PURGE_JOB_NAME,
    role: SESSION_PURGE_ROLE,
    intervalMs: SESSION_PURGE_INTERVAL_MS,
    async run({ signal, now, log }) {
      signal.throwIfAborted();
      const { ended } = await sessions.endLapsed({ signal });
      signal.throwIfAborted();
      const { deleted } = await sessions.purge({
        endedBefore: now() - retentionDays * DAY_MS,
        signal,
      });
      log.info({ ended, deleted }, 'lapsed sessions ended and old sessions purged');
    },
  });
}
