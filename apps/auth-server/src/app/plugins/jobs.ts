import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';

import {
  createAdvisoryJobLock,
  type JobClock,
  type JobDefinition,
  type JobLock,
  JobRunner,
  serverJobs,
  SERVICE_ROLES,
  type ServiceRole,
} from '../jobs';
import { METRICS_PLUGIN_NAME } from './metrics';

/** Options for {@link jobsPlugin}. Each defaults to what the server runs with. */
export interface JobsPluginOptions extends FastifyPluginOptions {
  /** Defaults to {@link serverJobs}. */
  jobs?: readonly JobDefinition[];
  /** The roles this node holds. Defaults to every role: one process runs every job. */
  roles?: readonly ServiceRole[];
  /** Defaults to a Postgres advisory lock over `fastify.dbPool`. */
  lock?: JobLock;
  clock?: JobClock;
  random?: () => number;
  shutdownTimeoutMs?: number;
}

export const JOBS_PLUGIN_NAME = '@qauth-labs/jobs';

/**
 * Background jobs (ADR-019 Decision 8).
 *
 * Builds the {@link JobRunner}, starts it once the server is ready and stops it
 * when the server closes. `fastify.close()`, which `SIGTERM` and `SIGINT` call
 * in `main.ts`, therefore waits for a running job up to the runner's shutdown
 * limit. This plugin's `onClose` runs before the database plugin's, which was
 * registered earlier, so the pool is still open while jobs stop.
 */
export const jobsPlugin = fp<JobsPluginOptions>(
  async (fastify: FastifyInstance, options: JobsPluginOptions) => {
    for (const decorator of [
      ...(options.lock ? [] : ['dbPool']),
      ...(options.jobs ? [] : ['repositories']),
    ]) {
      if (!fastify.hasDecorator(decorator)) {
        throw new Error(
          `The jobs plugin needs \`fastify.${decorator}\`: register the database plugin first`
        );
      }
    }

    const runner = new JobRunner({
      jobs: options.jobs ?? serverJobs(fastify),
      roles: options.roles ?? SERVICE_ROLES,
      lock: options.lock ?? createAdvisoryJobLock(fastify.dbPool, fastify.log),
      log: fastify.log,
      runs: fastify.metrics.jobRuns,
      ...(options.clock ? { clock: options.clock } : {}),
      ...(options.random ? { random: options.random } : {}),
      ...(options.shutdownTimeoutMs === undefined
        ? {}
        : { shutdownTimeoutMs: options.shutdownTimeoutMs }),
    });

    fastify.addHook('onReady', async () => {
      runner.start();
    });
    fastify.addHook('onClose', async () => {
      await runner.stop();
    });
  },
  {
    name: JOBS_PLUGIN_NAME,
    dependencies: [METRICS_PLUGIN_NAME],
  }
);

export default jobsPlugin;
