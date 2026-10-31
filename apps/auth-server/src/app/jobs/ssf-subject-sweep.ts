import type { FastifyInstance } from 'fastify';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const SSF_SUBJECT_SWEEP_JOB_NAME = 'ssf-subject-sweep';

/**
 * How often the sweep runs: hourly. A user subject outlives its relation by
 * at most this much, plus the time the events about the user take to be
 * delivered. It is a constant, not a setting: the sweep needs no grace of its
 * own, since it waits for the fan-out and the deliveries rather than for a
 * time.
 */
export const SSF_SUBJECT_SWEEP_INTERVAL_MS = 60 * 60_000;

/** The repository the sweep reads and deletes from. */
export type SsfSubjectSweepRepositories = Pick<FastifyInstance['repositories'], 'ssfStreams'>;

/**
 * The role whose nodes run the sweep: `api`, which serves the SSF stream
 * management routes and decides there which users a receiver may add.
 */
export const SSF_SUBJECT_SWEEP_ROLE = 'api';

/**
 * End the SSF user subjects whose relation has ended (#540, decided
 * 2026-10-31).
 *
 * A receiver may add a user only while the user is related to it (an active
 * consent, a live refresh token of its client, or a live refresh token for it
 * as a resource server). The subject used to stay until the receiver removed
 * it; now this sweep deletes it once the relation has ended (the user
 * withdrew the consent, the tokens were revoked or ran out, or the user was
 * disabled or deleted) and no event about the user can still reach the
 * stream: every such event has been fanned out, and none of the stream's
 * deliveries about the user is pending. So the withdrawal's own SET, sent
 * as CAEP `token-claims-change`, still goes out before the subject ends.
 *
 * Nothing is deleted where the relation ends: a withdrawal and its event
 * commit together, and the subject outlives them by at least the delivery.
 * Repeating the sweep deletes nothing new.
 */
export function createSsfSubjectSweepJob(repositories: SsfSubjectSweepRepositories): JobDefinition {
  return defineJob({
    name: SSF_SUBJECT_SWEEP_JOB_NAME,
    role: SSF_SUBJECT_SWEEP_ROLE,
    intervalMs: SSF_SUBJECT_SWEEP_INTERVAL_MS,
    async run({ signal, now, log }) {
      signal.throwIfAborted();
      const deleted = await repositories.ssfStreams.sweepUserSubjects(now());
      log.info({ deleted }, 'unrelated SSF user subjects ended');
    },
  });
}
