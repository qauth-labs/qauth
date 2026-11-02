import type { FastifyInstance } from 'fastify';

/**
 * GET /internal/metrics (#123, moved to the internal listener in #500)
 *
 * Exposes the process's prom-client registry in Prometheus text exposition
 * format for scraping: default process/runtime metrics plus the QAuth
 * counters and gauges (`plugins/metrics.ts`).
 *
 * It answers on the internal listener only (ADR-019 Decisions 1 and 8): the
 * public listener answers on a realm's hosts alone, and a scraper reaches a
 * process by its address, not by a realm's host. Its module admits only the
 * `metrics` peer role (`../route-manifest.ts`), so a scraper presents a
 * certificate that INTERNAL_PEER_ROLES maps to `metrics`; a single process
 * without the internal TLS files serves it in plain HTTP on a loopback
 * address only. It has no rate limit: the listener refuses every caller
 * without a role before any route, and a scraper polls at its own interval.
 *
 * The internal listener registers it under its module's prefix, `/internal`,
 * while METRICS_ENABLED is on.
 */
export default async function (fastify: FastifyInstance) {
  fastify.get('/metrics', async (_request, reply) => {
    const body = await fastify.metrics.registry.metrics();
    return reply
      .header('Content-Type', fastify.metrics.registry.contentType)
      .header('Cache-Control', 'no-store')
      .send(body);
  });
}
