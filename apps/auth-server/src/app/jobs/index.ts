import type { FastifyInstance } from 'fastify';

import type { JobDefinition } from './job-runner';
import { createPurgeExpiredJob } from './purge-expired';

export * from './advisory-lock';
export * from './job-runner';
export * from './purge-expired';

/**
 * Every job the auth server defines. The job runner starts those whose role
 * this node holds.
 */
export function serverJobs(fastify: FastifyInstance): JobDefinition[] {
  return [createPurgeExpiredJob(fastify.repositories)];
}
