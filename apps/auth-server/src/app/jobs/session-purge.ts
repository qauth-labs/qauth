import type { SessionService } from '@qauth-labs/fastify-plugin-sessions';
import { DAY_MS } from '@qauth-labs/shared-validation';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const SESSION_PURGE_JOB_NAME = 'session-purge';

/** One hour. */
export const SESSION_PURGE_INTERVAL_MS = 60 * 60_000;

/** The role whose nodes run the job: `web`, beside the session expiry job. */
export const SESSION_PURGE_ROLE = 'web';

/** `SESSION_RETENTION_DAYS`'s default. */
export const DEFAULT_SESSION_RETENTION_DAYS = 30;

/** What {@link createSessionPurgeJob} takes. */
export interface SessionPurgeJobOptions {
  /** `fastify.sessionService`. */
  readonly sessions: Pick<SessionService, 'purge'> | undefined;
  /** `SESSION_RETENTION_DAYS`: how long an ended session's row is kept. */
  readonly retentionDays: number;
}

/**
 * The browser session purge (ADR-019 Decision 3, issue #550): delete the rows
 * of sessions that ended, or passed their stored `expires_at`, more than
 * `SESSION_RETENTION_DAYS` ago. Until then the account and admin session
 * lists show them as ended. A live session is never deleted.
 *
 * A session that lapsed is marked by the `session-expiry` job at the time it
 * runs, and its retention counts from that mark; one whose `expires_at` is
 * older than the retention goes whether or not it was marked.
 *
 * It works in batches and stops between batches when the run's signal
 * aborts. Repeating it deletes nothing new, so a run cut short is finished by
 * the next one.
 *
 * Placed on the `web` role, beside the session expiry job.
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
      const { deleted } = await sessions.purge({
        endedBefore: now() - retentionDays * DAY_MS,
        signal,
      });
      log.info({ deleted }, 'old sessions purged');
    },
  });
}
