import { createHash } from 'node:crypto';

import type { FastifyBaseLogger } from 'fastify';

import type { JobLease, JobLock } from './job-runner';

/**
 * The job lock as a Postgres advisory lock (ADR-019 Decision 8).
 *
 * Each attempt takes a connection of its own from the pool and holds it for as
 * long as it holds the lock. The lock is session-level, so it lasts until it is
 * released, however long the run takes; a transaction-level lock would end with
 * the first transaction. And Postgres drops a session's advisory locks when the
 * session ends, so a node that dies, or whose connection drops, frees the job
 * without anyone releasing it.
 *
 * A session-level lock needs a real session: behind a pooler in transaction
 * mode, two statements of one attempt may run on different server connections.
 */

/** The part of a `pg` pool client the lock uses. */
export interface AdvisoryLockClient {
  query(text: string, values: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
  /** Back to the pool; with an error or `true`, the connection is closed instead. */
  release(destroy?: Error | boolean): void;
  on(event: 'error', listener: (error: Error) => void): unknown;
  on(event: 'end', listener: () => void): unknown;
  removeListener(event: 'error', listener: (error: Error) => void): unknown;
  removeListener(event: 'end', listener: () => void): unknown;
}

/** The part of a `pg` pool the lock uses; `fastify.dbPool` fits. */
export interface AdvisoryLockPool {
  connect(): Promise<AdvisoryLockClient>;
}

/** How long a release waits for the unlock before it closes the connection instead. */
export const ADVISORY_UNLOCK_TIMEOUT_MS = 5_000;

/**
 * The advisory lock key of a job: the first 64 bits of SHA-256 over a QAuth
 * prefix and the job name, as a signed `bigint` in decimal. Every node computes
 * the same key, and the prefix keeps it apart from keys other software on the
 * same database might choose.
 */
export function advisoryLockKey(jobName: string): string {
  return createHash('sha256').update(`qauth:job:${jobName}`).digest().readBigInt64BE(0).toString();
}

function asError(error: unknown): Error {
  return error instanceof Error ? error : new Error(String(error));
}

/**
 * A {@link JobLock} over Postgres advisory locks.
 *
 * @param pool - Where each attempt takes its connection from.
 * @param log - Where a lost or unreleasable lock is reported.
 */
export function createAdvisoryJobLock(pool: AdvisoryLockPool, log: FastifyBaseLogger): JobLock {
  return {
    async tryAcquire(jobName: string): Promise<JobLease | null> {
      const key = advisoryLockKey(jobName);
      const client = await pool.connect();
      const lost = new AbortController();
      let returned = false;

      // A pool client that is checked out has no error listener of its own,
      // so an unhandled connection error would crash the process. This one
      // also tells the run that the lock is gone.
      const onError = (error: Error): void => {
        if (returned || lost.signal.aborted) return;
        log.warn({ err: error, job: jobName }, 'job lock connection failed; the lock is lost');
        lost.abort(error);
      };
      const onEnd = (): void => onError(new Error('The job lock connection ended'));
      client.on('error', onError);
      client.on('end', onEnd);

      /** Return the connection to the pool, which listens for its errors again. */
      const giveBack = (): void => {
        returned = true;
        client.removeListener('error', onError);
        client.removeListener('end', onEnd);
        client.release();
      };
      /** Close the connection, which drops any lock it still holds. */
      const close = (reason: Error | true): void => {
        returned = true;
        client.release(reason);
      };

      let acquired: boolean;
      try {
        const { rows } = await client.query('SELECT pg_try_advisory_lock($1::bigint) AS acquired', [
          key,
        ]);
        acquired = rows[0]?.['acquired'] === true;
      } catch (error) {
        close(asError(error));
        throw error;
      }
      if (!acquired) {
        giveBack();
        return null;
      }

      let releasing: Promise<void> | undefined;
      const unlock = async (): Promise<void> => {
        if (lost.signal.aborted) {
          close(true);
          return;
        }
        let timer: ReturnType<typeof setTimeout> | undefined;
        try {
          const { rows } = await Promise.race([
            client.query('SELECT pg_advisory_unlock($1::bigint) AS released', [key]),
            new Promise<never>((_, reject) => {
              timer = setTimeout(
                () => reject(new Error('The job unlock timed out')),
                ADVISORY_UNLOCK_TIMEOUT_MS
              );
            }),
          ]);
          if (rows[0]?.['released'] === true) {
            giveBack();
          } else {
            log.warn({ job: jobName }, 'job lock was not held at release; closing its connection');
            close(true);
          }
        } catch (error) {
          log.warn(
            { err: error, job: jobName },
            'job lock could not be released; closing its connection'
          );
          close(asError(error));
        } finally {
          clearTimeout(timer);
        }
      };

      return {
        lost: lost.signal,
        release(): Promise<void> {
          releasing ??= unlock();
          return releasing;
        },
      };
    },
  };
}
