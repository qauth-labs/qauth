import type { ServiceRole } from '@qauth-labs/server-config';
import type { FastifyInstance } from 'fastify';
import fp from 'fastify-plugin';

import { createReadinessRegistry, type ReadinessRegistry } from '../helpers/readiness';
import { holdsSigner } from '../service-roles';

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The process's readiness checks (#500), which `GET /ready` runs. A role,
     * or a plugin of one, registers the check of what it depends on before
     * the server is ready (`helpers/readiness.ts`).
     */
    readiness: ReadinessRegistry;
  }
}

export const READINESS_PLUGIN_NAME = '@qauth-labs/readiness';

/** Decorate the instance with an empty readiness registry, logging to its logger. */
export const readinessPlugin = fp(
  async (fastify: FastifyInstance) => {
    fastify.decorate('readiness', createReadinessRegistry({ log: fastify.log }));
  },
  { name: READINESS_PLUGIN_NAME }
);

/**
 * The roles that need Redis: it still holds the rate limits and the
 * single-use stores the browser, API and admin routes use, so a process of
 * one of them cannot serve without it.
 */
export const REDIS_READINESS_ROLES: readonly ServiceRole[] = ['web', 'api', 'admin'];

/**
 * How long a KEK check's success stands: unwrapping a canary may be a call to
 * a KMS, which a probe every few seconds would otherwise make each time.
 */
export const KEK_CHECK_REUSE_MS = 30_000;

/**
 * How long a KEK check's failure stands: a KMS that refuses at once, a
 * disabled key or a throttled account, would otherwise take a call for every
 * request to `/ready`, from any caller.
 */
export const KEK_CHECK_FAILURE_REUSE_MS = 5_000;

/** The parts of the app the role checks read. */
export type RoleReadinessSource = Pick<FastifyInstance, 'readiness' | 'dbPool' | 'redis'> & {
  readonly checkKeyCustody?: () => Promise<void>;
  readonly repositories: {
    readonly eventDeliveries?: { deliveryLagSeconds(now: number): Promise<number> };
  };
};

/**
 * Register the checks of what `roles` need (#500):
 *
 * - `database`, on every process: Postgres answers `SELECT 1`;
 * - `redis`, on `web`, `api` and `admin`: Redis answers `PING`;
 * - `kek`, on `signer`: the KEK provider is usable and unwraps a stored key
 *   per KEK reference in use (`checkKeyCustody` of the signer plugin);
 * - `outbox`, on `delivery`: the event outbox reads, through the query the
 *   delivery role's lag gauge runs.
 *
 * Call it once the plugins it reads are registered.
 */
export function registerRoleReadinessChecks(
  fastify: RoleReadinessSource,
  roles: readonly ServiceRole[]
): void {
  fastify.readiness.register({
    name: 'database',
    run: () => fastify.dbPool.query('SELECT 1'),
  });
  if (roles.some((role) => REDIS_READINESS_ROLES.includes(role))) {
    fastify.readiness.register({ name: 'redis', run: () => fastify.redis.ping() });
  }
  if (holdsSigner(roles)) {
    const check = fastify.checkKeyCustody;
    if (check === undefined) {
      throw new Error('The kek readiness check needs the signer plugin registered first');
    }
    fastify.readiness.register({
      name: 'kek',
      run: check,
      reuseSuccessMs: KEK_CHECK_REUSE_MS,
      reuseFailureMs: KEK_CHECK_FAILURE_REUSE_MS,
    });
  }
  if (roles.includes('delivery')) {
    const outbox = fastify.repositories.eventDeliveries;
    if (outbox === undefined) {
      throw new Error('The outbox readiness check needs the eventDeliveries repository');
    }
    fastify.readiness.register({
      name: 'outbox',
      run: () => outbox.deliveryLagSeconds(Date.now()),
    });
  }
}
