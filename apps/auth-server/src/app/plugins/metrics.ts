import { hasRepository } from '@qauth-labs/fastify-plugin-db';
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
   * Client-secret checks refused with 503 before any hash was computed,
   * because `PASSWORD_HASH_QUEUE_LIMIT` Argon2 jobs were already waiting
   * (#751).
   */
  clientSecretChecksShed: Counter;
  /**
   * Background job runs (ADR-019 Decision 8). Labelled by `job` (the job's
   * name) and `result` = `success` | `failure` | `timeout`. A run skipped
   * because another node holds the job's lock is not counted; a lock that
   * cannot be taken counts as a `failure`.
   */
  jobRuns: Counter<'job' | 'result'>;
  /**
   * Events the retention job deleted (#536), by `category` = `user` |
   * `admin`.
   */
  eventsRetentionDeleted: Counter<'category'>;
  /**
   * Browser session cache reads (ADR-019 Decision 3, #469). Labelled by
   * `result` = `hit` | `miss` | `revoked` | `error`; hits over all reads is the
   * cache hit rate.
   */
  sessionCacheLookups: Counter<'result'>;
  /** Postgres reads of a browser session (#469), by `result` = `ok` | `error`. */
  sessionPostgresReads: Counter<'result'>;
  /**
   * Conditional `last_seen_at` updates of a browser session (#469), by
   * `result` = `written` | `skipped` (another node wrote first) | `error`.
   */
  sessionLastSeenWrites: Counter<'result'>;
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
 * process/Node metrics, and defines the QAuth auth and session counters and, when the
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

    const clientSecretChecksShed = new Counter({
      name: 'qauth_client_secret_checks_shed_total',
      help: 'Client-secret checks refused with 503 because the Argon2 queue was full.',
      registers: [registry],
    });

    const jobRuns = new Counter({
      name: 'qauth_job_runs_total',
      help: 'Total background job runs by job and outcome.',
      labelNames: ['job', 'result'] as const,
      registers: [registry],
    });

    const eventsRetentionDeleted = new Counter({
      name: 'qauth_events_retention_deleted_total',
      help: 'Events the retention job deleted, by category.',
      labelNames: ['category'] as const,
      registers: [registry],
    });

    const sessionCacheLookups = new Counter({
      name: 'qauth_session_cache_lookups_total',
      help: 'Browser session cache reads by outcome; hit over all is the cache hit rate.',
      labelNames: ['result'] as const,
      registers: [registry],
    });

    const sessionPostgresReads = new Counter({
      name: 'qauth_session_postgres_reads_total',
      help: 'Postgres reads of a browser session by outcome.',
      labelNames: ['result'] as const,
      registers: [registry],
    });

    const sessionLastSeenWrites = new Counter({
      name: 'qauth_session_last_seen_writes_total',
      help: 'Conditional last-seen updates of a browser session by outcome.',
      labelNames: ['result'] as const,
      registers: [registry],
    });

    // The event store's read lag (#457): how long the oldest committed event
    // has been held back from readers by an older transaction still open. It
    // is read from the database at each scrape, so it exists only when the
    // database plugin, registered before this one in the app, is present, and
    // only on a process whose roles read the event store (#495: `delivery`).
    // A failed read reports NaN, not a stale or a reassuring value.
    if (fastify.hasDecorator('repositories') && hasRepository(fastify.repositories, 'events')) {
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

    // The age of each category's oldest event (#536): about the realm's
    // retention while the retention job keeps up, and growing past it when
    // the job stops or a destination holds events back. Read at each scrape,
    // through the retention repository, so it needs a database user that may
    // read events, on a process whose roles load it (#495: `delivery`); a
    // failed read reports NaN.
    if (
      fastify.hasDecorator('repositories') &&
      hasRepository(fastify.repositories, 'eventRetention')
    ) {
      new Gauge({
        name: 'qauth_events_oldest_age_seconds',
        help: "Seconds since each category's oldest stored event was written; 0 when it has none.",
        labelNames: ['category'] as const,
        registers: [registry],
        async collect() {
          try {
            const oldest = await fastify.repositories.eventRetention.oldestEventTimes();
            const now = Date.now();
            for (const category of ['user', 'admin'] as const) {
              const time = oldest[category];
              this.set({ category }, time === null ? 0 : Math.max(0, now - time) / 1000);
            }
          } catch (error) {
            fastify.log.warn({ err: error }, 'Could not read the oldest event ages for /metrics');
            for (const category of ['user', 'admin'] as const) {
              this.set({ category }, Number.NaN);
            }
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

    const metrics: AppMetrics = {
      registry,
      loginAttempts,
      tokensIssued,
      clientSecretChecksShed,
      jobRuns,
      eventsRetentionDeleted,
      sessionCacheLookups,
      sessionPostgresReads,
      sessionLastSeenWrites,
    };
    fastify.decorate('metrics', metrics);

    fastify.log.debug('Metrics plugin registered');
  },
  {
    name: METRICS_PLUGIN_NAME,
  }
);

export default metricsPlugin;
