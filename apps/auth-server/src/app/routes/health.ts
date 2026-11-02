import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../config/env';
import { noStore, probeRateLimitHook, serviceRolesSchema } from '../helpers/probe-routes';

/** What `GET /health` answers. */
const healthResponseSchema = z
  .object({
    status: z.literal('ok').describe('Always `ok`: the process answers.'),
    timestamp: z.iso.datetime().describe('When the process answered.'),
    roles: serviceRolesSchema,
  })
  .describe('The process answers. Its dependencies are what `GET /ready` checks.');

/**
 * GET /health — liveness (#500).
 *
 * Answers 200 while the process serves, with the roles it runs. It checks no
 * dependency: a process whose database or Redis is down is alive, and
 * restarting it would not bring them back. Whether the process can serve
 * what its roles need is `GET /ready` (`./ready.ts`).
 *
 * It answers on any host and carries no realm data (`surface: 'none'`,
 * ADR-019 Decision 1), and is rate-limited per client address in the
 * process's memory, not in Redis (`helpers/probe-routes.ts`).
 */
export default async function (fastify: FastifyInstance) {
  const roles = [...env.SERVICE_ROLES];
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/health',
    {
      schema: {
        description:
          'Liveness: answers 200 while the process serves, with the service roles it runs. It checks no dependency; `GET /ready` does. Answers on any host and carries no realm data.',
        tags: ['System'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [429],
        response: { 200: healthResponseSchema },
      },
      config: { surface: 'none', rateLimit: false },
      onRequest: probeRateLimitHook({
        max: env.HEALTH_RATE_LIMIT_MAX,
        windowSeconds: env.HEALTH_RATE_LIMIT_WINDOW,
        enabled: env.RATE_LIMIT_ENABLED,
      }),
    },
    async (_request, reply) =>
      noStore(reply).send({ status: 'ok', timestamp: new Date().toISOString(), roles })
  );
}
