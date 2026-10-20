import type { FastifyInstance } from 'fastify';

import { defineJob, type JobDefinition } from './job-runner';

/** The job's name: its lock, its log lines and its metric label. */
export const PURGE_EXPIRED_JOB_NAME = 'purge-expired';

/** One hour. */
export const PURGE_EXPIRED_INTERVAL_MS = 60 * 60_000;

/** The repositories whose expired rows the job deletes. */
export type PurgeExpiredRepositories = Pick<
  FastifyInstance['repositories'],
  'authorizationCodes' | 'refreshTokens' | 'emailVerificationTokens' | 'oid4vpRequestStates'
>;

/**
 * Delete the rows whose lifetime has ended from the four tables nothing else
 * cleans up: authorization codes, refresh tokens, email verification tokens
 * and OID4VP request states.
 *
 * Each table's own `deleteExpired` decides what has expired, so a row is gone
 * only once no read needs it. An OID4VP request state, for example, stays until
 * its Response Code has expired too, and a refresh token stays until its whole
 * family has expired, so a replay of a rotated token still revokes the family.
 * Repeating the job deletes nothing new, so a run cut short is simply finished
 * by the next one.
 *
 * Placed on the `api` role: the token endpoint is where codes and refresh
 * tokens are redeemed.
 */
export function createPurgeExpiredJob(repositories: PurgeExpiredRepositories): JobDefinition {
  const purges: ReadonlyArray<readonly [table: string, purge: () => Promise<number>]> = [
    ['authorization_codes', () => repositories.authorizationCodes.deleteExpired()],
    ['refresh_tokens', () => repositories.refreshTokens.deleteExpired()],
    [
      'email_verification_tokens',
      async () => (await repositories.emailVerificationTokens.deleteExpired()).length,
    ],
    ['oid4vp_request_states', () => repositories.oid4vpRequestStates.deleteExpired()],
  ];

  return defineJob({
    name: PURGE_EXPIRED_JOB_NAME,
    role: 'api',
    intervalMs: PURGE_EXPIRED_INTERVAL_MS,
    async run({ signal, log }) {
      const deleted: Record<string, number> = {};
      for (const [table, purge] of purges) {
        signal.throwIfAborted();
        deleted[table] = await purge();
      }
      log.info({ deleted }, 'expired rows purged');
    },
  });
}
