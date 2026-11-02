import type { FastifyInstance } from 'fastify';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const APPROVAL_EXPIRY_JOB_NAME = 'approval-expiry';

/**
 * How often the sweep runs: every minute. An approval is refused the moment
 * it expires whatever the sweep does; the sweep only retires its nonce, so a
 * copy of the table taken in the minute after the expiry is all it leaves to
 * chance.
 */
export const APPROVAL_EXPIRY_INTERVAL_MS = 60_000;

/** The most approvals one pass of a run marks before it looks again. */
export const APPROVAL_EXPIRY_BATCH = 500;

/** The repository the sweep writes. */
export type ApprovalExpiryRepositories = Pick<FastifyInstance['repositories'], 'adminApprovals'>;

/**
 * The role whose nodes run the sweep: `admin`, whose listener files, reads
 * and consumes approvals.
 */
export const APPROVAL_EXPIRY_ROLE = 'admin';

/**
 * Retire the approvals that expired unused (#901). An approval for a security
 * operation stores the nonce its `op_hash` was computed with, and that hash
 * binds the operation's body, which the approval never stores and which may
 * hold a secret. While the nonce is there, a copy of the table would let a
 * guessed body be tested against the hash; so a move that closes an approval
 * overwrites the nonce, and this sweep does the same for one whose time ran
 * out: it stores `expired` on every approval still `pending` or `approved`
 * past its expiry, with a random nonce.
 *
 * One the operation's transaction holds is skipped and found again by the
 * next pass or run. Repeating the sweep marks nothing twice.
 */
export function createApprovalExpiryJob(repositories: ApprovalExpiryRepositories): JobDefinition {
  return defineJob({
    name: APPROVAL_EXPIRY_JOB_NAME,
    role: APPROVAL_EXPIRY_ROLE,
    intervalMs: APPROVAL_EXPIRY_INTERVAL_MS,
    async run({ signal, now, log }) {
      let expired = 0;
      for (;;) {
        signal.throwIfAborted();
        const marked = await repositories.adminApprovals.expireLapsed(now(), APPROVAL_EXPIRY_BATCH);
        expired += marked;
        if (marked < APPROVAL_EXPIRY_BATCH) break;
      }
      log.info({ expired }, 'expired approvals retired');
    },
  });
}
