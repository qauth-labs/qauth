import type { FastifyInstance } from 'fastify';

import { env } from '../../config/env';

/**
 * GET /metrics (#123)
 *
 * Exposes the prom-client registry in Prometheus text exposition format for
 * scraping. Includes default process/runtime metrics plus the QAuth auth
 * counters (`qauth_login_attempts_total`, `qauth_tokens_issued_total`).
 *
 * The endpoint is unauthenticated and rate-limit-exempt so a scraper can poll
 * it at a high frequency; protect it at the reverse proxy / network layer (e.g.
 * restrict to the metrics subnet) in production.
 */
export default async function (fastify: FastifyInstance) {
  if (!env.METRICS_ENABLED) {
    fastify.log.warn('Metrics endpoint is DISABLED via METRICS_ENABLED=false');
    return;
  }

  fastify.get(
    '/metrics',
    {
      schema: {
        description:
          'Prometheus metrics endpoint. Returns process/runtime metrics plus auth counters in Prometheus text exposition format.',
        tags: ['System'],
      },
      // High-frequency scrape target — exempt from rate limiting.
      config: { rateLimit: false },
    },
    async (_request, reply) => {
      const body = await fastify.metrics.registry.metrics();
      return reply.header('Content-Type', fastify.metrics.registry.contentType).send(body);
    }
  );
}
