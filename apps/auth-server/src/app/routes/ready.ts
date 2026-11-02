import type { FastifyInstance } from 'fastify';
import type { ZodTypeProvider } from 'fastify-type-provider-zod';
import { z } from 'zod';

import { env } from '../../config/env';
import { describeProblem } from '../api-conventions/error-classes';
import { PROBLEM_MEDIA_TYPE, problemResponses } from '../api-conventions/problem';
import { noStore, probeRateLimitHook, serviceRolesSchema } from '../helpers/probe-routes';

/** One check's result. */
const checkResultSchema = z
  .object({
    status: z.enum(['ok', 'fail']).describe('Whether the check passed.'),
    reason: z
      .enum(['error', 'timeout'])
      .optional()
      .describe(
        'Why a failed check failed: the dependency refused or errored, or did not answer in time.'
      ),
  })
  .describe('The result of one readiness check.');

/** Each check the roles registered, by name, with its result. */
const checksSchema = z
  .record(z.string(), checkResultSchema)
  .describe(
    'Each check the roles registered, by name: `database` on every process, `redis` on `web`, `api` and `admin`, `kek` on `signer`, `outbox` on `delivery`.'
  );

/** What `GET /ready` answers when every check passed. */
const readyResponseSchema = z
  .object({
    status: z.literal('ok').describe('Every check passed.'),
    roles: serviceRolesSchema,
    checks: checksSchema,
  })
  .describe('The readiness checks of this process and their results.');

/**
 * GET /ready — readiness (#500).
 *
 * Runs the checks the process's roles registered (`helpers/readiness.ts`),
 * each bounded by its timeout, and answers 200 when every one passed. When
 * one failed it answers 503 with an RFC 9457 problem document, as every
 * route outside the OAuth protocol endpoints answers an error (ADR-019
 * Decision 7): code `service_unavailable`, a `detail` naming the failed
 * checks, and the extension members `roles` and `checks`, each check's
 * result. A load balancer or an orchestrator sends traffic to the process
 * only while it answers 200.
 *
 * It answers on any host and carries no realm data (`surface: 'none'`,
 * ADR-019 Decision 1): a result names the check and a reason from a closed
 * set, never the error, which goes to the log. It is rate-limited per client
 * address in the process's memory, not in Redis (`helpers/probe-routes.ts`),
 * so it still answers, and says so, while Redis is down.
 */
export default async function (fastify: FastifyInstance) {
  const roles = [...env.SERVICE_ROLES];
  fastify.withTypeProvider<ZodTypeProvider>().get(
    '/ready',
    {
      schema: {
        description:
          'Readiness: runs the checks this process needs for its service roles (the database, Redis, the KEK, the event outbox) and answers 200 when every one passes. When one fails it answers 503 with a `service_unavailable` problem document whose extension members `roles` and `checks` carry the roles and the result of each check, as the 200 answer does. Answers on any host and carries no realm data.',
        tags: ['System'],
        'x-qauth-stability': 'stable',
        'x-qauth-errors': [429],
        response: { 200: readyResponseSchema, ...problemResponses(503) },
      },
      config: { surface: 'none', rateLimit: false },
      onRequest: probeRateLimitHook({
        max: env.HEALTH_RATE_LIMIT_MAX,
        windowSeconds: env.HEALTH_RATE_LIMIT_WINDOW,
        enabled: env.RATE_LIMIT_ENABLED,
      }),
    },
    async (request, reply) => {
      const report = await fastify.readiness.run();
      if (report.ready) {
        return noStore(reply).status(200).send({ status: 'ok', roles, checks: report.checks });
      }
      const failed = Object.entries(report.checks)
        .filter(([, result]) => result.status === 'fail')
        .map(([name]) => name);
      const { type, title, status, code } = describeProblem('service_unavailable');
      return noStore(reply)
        .status(status)
        .type(PROBLEM_MEDIA_TYPE)
        .send({
          type,
          title,
          status,
          // Names the checks only: each error went to the log.
          detail: `A readiness check failed: ${failed.join(', ')}.`,
          instance: '/ready',
          code,
          trace_id: request.id,
          roles,
          checks: report.checks,
        });
    }
  );
}
