import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';
import { collectDefaultMetrics, Counter, Registry } from 'prom-client';

/**
 * Application metrics exposed to Prometheus.
 *
 * Decorated onto the Fastify instance as `fastify.metrics` so routes and helpers
 * can increment counters without importing a global singleton. The `registry`
 * is what the `GET /metrics` route serialises (#123).
 */
export interface AppMetrics {
  /** prom-client registry backing the `/metrics` endpoint. */
  registry: Registry;
  /**
   * Login outcomes (#123). Labelled by `result` = `success` | `failure`, and
   * `reason` for failures (e.g. `invalid_credentials`, `locked_out`).
   */
  loginAttempts: Counter<'result' | 'reason'>;
  /**
   * Tokens issued (#123, #126). Labelled by `type` = `access` | `refresh` and
   * `grant_type` (e.g. `password`, `authorization_code`, `refresh_token`,
   * `client_credentials`, `token-exchange`).
   */
  tokensIssued: Counter<'type' | 'grant_type'>;
}

declare module 'fastify' {
  interface FastifyInstance {
    metrics: AppMetrics;
  }
}

export const METRICS_PLUGIN_NAME = '@qauth-labs/metrics';

/**
 * Metrics plugin (#123, #126).
 *
 * Creates an isolated prom-client {@link Registry} (so tests and multiple
 * instances do not clash on the global default registry), registers default
 * process/Node metrics, and defines the QAuth auth counters. Decorates the
 * Fastify instance with {@link AppMetrics}.
 */
export const metricsPlugin = fp<FastifyPluginOptions>(
  async (fastify: FastifyInstance) => {
    const registry = new Registry();
    registry.setDefaultLabels({ app: 'auth-server' });

    // Default process/runtime metrics (CPU, memory, event-loop lag, GC, ...).
    collectDefaultMetrics({ register: registry });

    const loginAttempts = new Counter({
      name: 'qauth_login_attempts_total',
      help: 'Total login attempts by outcome.',
      labelNames: ['result', 'reason'] as const,
      registers: [registry],
    });

    const tokensIssued = new Counter({
      name: 'qauth_tokens_issued_total',
      help: 'Total tokens issued by token type and grant type.',
      labelNames: ['type', 'grant_type'] as const,
      registers: [registry],
    });

    const metrics: AppMetrics = { registry, loginAttempts, tokensIssued };
    fastify.decorate('metrics', metrics);

    fastify.log.debug('Metrics plugin registered');
  },
  {
    name: METRICS_PLUGIN_NAME,
  }
);

export default metricsPlugin;
