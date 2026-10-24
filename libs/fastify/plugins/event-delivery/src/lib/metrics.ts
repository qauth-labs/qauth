import type { EventDeliveriesRepository } from '@qauth-labs/infra-db';
import type { DeliveryAttemptResult, DeliveryMetrics } from '@qauth-labs/server-event-delivery';
import { Counter, Gauge, type Registry } from 'prom-client';

/** The metric names of the delivery role (issue #460). */
export const DELIVERY_METRIC_NAMES = Object.freeze({
  pending: 'qauth_events_pending',
  lag: 'qauth_events_delivery_lag_seconds',
  attempts: 'qauth_events_delivery_attempts_total',
} as const);

/** What {@link registerDeliveryMetrics} reads and where it logs a failed read. */
export interface DeliveryMetricsSources {
  readonly store: Pick<EventDeliveriesRepository, 'pendingByKind' | 'deliveryLagSeconds'>;
  /** The route kinds this node delivers: each has a pending series, 0 when nothing waits. */
  readonly kinds: readonly string[];
  /** The role's clock, in epoch milliseconds. */
  readonly now: () => number;
  readonly warn: (error: unknown, message: string) => void;
}

/**
 * Register the delivery role's metrics on `registry`:
 *
 * - `qauth_events_pending{kind}` — deliveries not finished yet, read from
 *   the queue at each scrape;
 * - `qauth_events_delivery_lag_seconds` — how long the oldest event that
 *   waits for a delivery has waited, the fan-out included;
 * - `qauth_events_delivery_attempts_total{kind,result}` — attempts by route
 *   kind and result (`delivered`, `retry`, `failed`): `retry` and `failed`
 *   are the failures, `failed` the deliveries that ended failed.
 *
 * A read that fails reports NaN, not a stale or a reassuring value.
 *
 * @returns where the role counts its attempts
 */
export function registerDeliveryMetrics(
  registry: Registry,
  sources: DeliveryMetricsSources
): DeliveryMetrics {
  new Gauge({
    name: DELIVERY_METRIC_NAMES.pending,
    help: 'Event deliveries not finished yet (pending or claimed), by route kind.',
    labelNames: ['kind'] as const,
    registers: [registry],
    async collect() {
      this.reset();
      try {
        const pending = await sources.store.pendingByKind();
        for (const kind of sources.kinds) this.set({ kind }, pending[kind] ?? 0);
        for (const [kind, count] of Object.entries(pending)) this.set({ kind }, count);
      } catch (error) {
        sources.warn(error, 'Could not read the pending event deliveries for /metrics');
        for (const kind of sources.kinds) this.set({ kind }, Number.NaN);
      }
    },
  });

  new Gauge({
    name: DELIVERY_METRIC_NAMES.lag,
    help: 'Seconds the oldest event that waits for a delivery has waited, from its time; 0 when none waits.',
    registers: [registry],
    async collect() {
      try {
        this.set(await sources.store.deliveryLagSeconds(sources.now()));
      } catch (error) {
        sources.warn(error, 'Could not read the event delivery lag for /metrics');
        this.set(Number.NaN);
      }
    },
  });

  const attempts = new Counter({
    name: DELIVERY_METRIC_NAMES.attempts,
    help: 'Event delivery attempts by route kind and result: delivered, retry (failed, tried again later) or failed (failed for good).',
    labelNames: ['kind', 'result'] as const,
    registers: [registry],
  });

  return {
    attempt(kind: string, result: DeliveryAttemptResult): void {
      attempts.inc({ kind, result });
    },
  };
}
