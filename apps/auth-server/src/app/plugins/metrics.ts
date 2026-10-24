import type { FastifyInstance, FastifyPluginOptions } from 'fastify';
import fp from 'fastify-plugin';
import { collectDefaultMetrics, Counter, Gauge, Registry } from 'prom-client';

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
  /**
   * Background job runs (ADR-019 Decision 8). Labelled by `job` (the job's
   * name) and `result` = `success` | `failure` | `timeout`. A run skipped
   * because another node holds the job's lock is not counted; a lock that
   * cannot be taken counts as a `failure`.
   */
  jobRuns: Counter<'job' | 'result'>;
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
 * process/Node metrics, and defines the QAuth auth counters and, when the
 * database plugin is registered, the event store lag gauge. With the event
 * telemetry on, it also serves that export's drop counter. Decorates the
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

    const jobRuns = new Counter({
      name: 'qauth_job_runs_total',
      help: 'Total background job runs by job and outcome.',
      labelNames: ['job', 'result'] as const,
      registers: [registry],
    });

    // The event store's read lag (#457): how long the oldest committed event
    // has been held back from readers by an older transaction still open. It
    // is read from the database at each scrape, so it exists only when the
    // database plugin, registered before this one in the app, is present. A
    // failed read reports NaN, not a stale or a reassuring value.
    if (fastify.hasDecorator('repositories')) {
      new Gauge({
        name: 'qauth_events_oldest_unread_age_seconds',
        help: 'Seconds the oldest committed event has been held back from readers by an older open transaction; 0 when none is.',
        registers: [registry],
        async collect() {
          try {
            this.set(await fastify.repositories.events.oldestUnreadEventAge());
          } catch (error) {
            fastify.log.warn({ err: error }, 'Could not read the event store lag for /metrics');
            this.set(Number.NaN);
          }
        },
      });
    }

    // Event log records the OpenTelemetry export dropped (#541). The export
    // owns the counter, since it exists before this plugin; it is here only
    // when OTEL_EVENTS_ENABLED is on.
    if (fastify.eventTelemetry !== undefined) {
      registry.registerMetric(fastify.eventTelemetry.droppedRecords);
    }

    const metrics: AppMetrics = { registry, loginAttempts, tokensIssued, jobRuns };
    fastify.decorate('metrics', metrics);

    fastify.log.debug('Metrics plugin registered');
  },
  {
    name: METRICS_PLUGIN_NAME,
  }
);

export default metricsPlugin;
