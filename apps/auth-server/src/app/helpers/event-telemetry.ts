import { context } from '@opentelemetry/api';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';
import { defaultResource, resourceFromAttributes } from '@opentelemetry/resources';
import { LoggerProvider, type LogRecordExporter } from '@opentelemetry/sdk-logs';
import type { EventTelemetrySink } from '@qauth-labs/fastify-plugin-db';
import type { EventTelemetryEnv } from '@qauth-labs/server-config';
import { EventValidationError } from '@qauth-labs/shared-events';
import type { FastifyBaseLogger } from 'fastify';
import { Counter } from 'prom-client';

import {
  DEFAULT_EVENT_LOG_QUEUE_LIMITS,
  DropOldestLogRecordProcessor,
  type EventLogQueueLimits,
} from './event-log-queue';
import { eventLogRecord } from './event-log-record';

/**
 * The OpenTelemetry log export of events (ADR-018 §3, ADR-019 Decision 8,
 * issue #541): every event the auth server commits is sent as a log record
 * to the operator's collector, over OTLP/HTTP. Off by default.
 *
 * It is telemetry, not delivery. A record waits in a bounded queue that drops
 * its oldest record when full, a failed export is not retried past the
 * exporter's own retries, and a crash between the commit and the export
 * loses the record. Each drop is counted in
 * `qauth_events_telemetry_dropped_total`. Export never fails or slows a
 * request. The event API and webhooks read the event store and carry the
 * delivery guarantee.
 *
 * The collector is the operator's own, often on a private network, so the
 * export goes through the OpenTelemetry SDK's HTTP exporter, not the egress
 * client that guards destinations a client or a user names. The exporter
 * reads the standard `OTEL_EXPORTER_OTLP_*` variables from the environment
 * itself, with their standard meaning; the env schema has already checked
 * them.
 */

/** The settings the export reads, from the parsed environment. */
export interface EventTelemetrySettings {
  /** `OTEL_EVENTS_ENABLED`. Off: no exporter is created and nothing is sent. */
  readonly enabled: boolean;
  /** `OTEL_SERVICE_NAME`, the `service.name` of every record's resource. */
  readonly serviceName: string;
  /**
   * The exporter's timeout, in milliseconds: `OTEL_EXPORTER_OTLP_LOGS_TIMEOUT`,
   * else `OTEL_EXPORTER_OTLP_TIMEOUT`, else the OpenTelemetry default. The
   * queue's guard against an export that never reports waits longer.
   */
  readonly exporterTimeoutMillis: number;
}

/** The OpenTelemetry default of `OTEL_EXPORTER_OTLP_TIMEOUT`. */
export const OTLP_DEFAULT_TIMEOUT_MILLIS = 10_000;

/** How much longer than the exporter's timeout the queue waits before it gives a batch up. */
const EXPORT_GUARD_MARGIN_MILLIS = 5000;

/** The instrumentation scope of the records. */
export const EVENT_LOGGER_NAME = 'qauth.events';

/** The export's settings, from the parsed environment. */
export function eventTelemetrySettings(
  env: Pick<
    EventTelemetryEnv,
    | 'OTEL_EVENTS_ENABLED'
    | 'OTEL_SERVICE_NAME'
    | 'OTEL_EXPORTER_OTLP_TIMEOUT'
    | 'OTEL_EXPORTER_OTLP_LOGS_TIMEOUT'
  >
): EventTelemetrySettings {
  return {
    enabled: env.OTEL_EVENTS_ENABLED,
    serviceName: env.OTEL_SERVICE_NAME,
    exporterTimeoutMillis:
      env.OTEL_EXPORTER_OTLP_LOGS_TIMEOUT ??
      env.OTEL_EXPORTER_OTLP_TIMEOUT ??
      OTLP_DEFAULT_TIMEOUT_MILLIS,
  };
}

/** The running export: the event store's sink, its drop counter and its controls. */
export interface EventTelemetry extends EventTelemetrySink {
  /**
   * `qauth_events_telemetry_dropped_total`, by `reason`: `queue_full` (the
   * queue was full and the record was its oldest) or `export_failed` (the
   * collector refused the batch or could not be reached). Registered on no
   * registry; the metrics plugin adds it to `/metrics`.
   */
  readonly droppedRecords: Counter<'reason'>;
  /** How many records wait to be exported, the batch being sent excluded. */
  readonly queueLength: number;
  /** The most records the queue holds. */
  readonly maxQueueSize: number;
  /** Send every queued record now and wait for the exports. */
  forceFlush(): Promise<void>;
  /** Send what is queued, for at most a few seconds, then stop. */
  shutdown(): Promise<void>;
}

/** What {@link createEventTelemetry} takes beside the settings. */
export interface EventTelemetryOptions {
  /** The server's log, for a refused event and the records left at shutdown. */
  readonly log: FastifyBaseLogger;
  /** The queue's sizes and times, for a test; the defaults otherwise. */
  readonly limits?: Partial<EventLogQueueLimits>;
  /** An exporter in place of the OTLP one, for a test. */
  readonly exporter?: LogRecordExporter;
}

/**
 * Start the export, or do nothing when it is off.
 *
 * @returns the export, or `undefined` when `OTEL_EVENTS_ENABLED` is off: then
 *   no exporter exists and no request is ever sent
 */
export function createEventTelemetry(
  settings: EventTelemetrySettings,
  options: EventTelemetryOptions
): EventTelemetry | undefined {
  if (!settings.enabled) return undefined;
  const { log } = options;

  const droppedRecords = new Counter({
    name: 'qauth_events_telemetry_dropped_total',
    help: 'Event log records not exported to the OpenTelemetry collector, by reason.',
    labelNames: ['reason'] as const,
    registers: [],
  });
  // Both series exist from the start, so a rate over them is never empty.
  droppedRecords.inc({ reason: 'queue_full' }, 0);
  droppedRecords.inc({ reason: 'export_failed' }, 0);

  const limits: EventLogQueueLimits = {
    ...DEFAULT_EVENT_LOG_QUEUE_LIMITS,
    exportTimeoutMillis: settings.exporterTimeoutMillis + EXPORT_GUARD_MARGIN_MILLIS,
    ...options.limits,
  };
  const processor = new DropOldestLogRecordProcessor(
    options.exporter ?? new OTLPLogExporter(),
    limits,
    (count, reason) => droppedRecords.inc({ reason }, count)
  );
  const provider = new LoggerProvider({
    resource: defaultResource().merge(
      resourceFromAttributes({ 'service.name': settings.serviceName })
    ),
    processors: [processor],
  });
  const logger = provider.getLogger(EVENT_LOGGER_NAME);

  return {
    droppedRecords,
    get queueLength() {
      return processor.queueLength;
    },
    maxQueueSize: limits.maxQueueSize,

    record(event) {
      try {
        // The context is the caller's: after the commit, still the request's,
        // so an active span gives the record its trace id and span id.
        logger.emit(eventLogRecord(event, context.active()));
      } catch (error) {
        log.error(
          {
            eventId: event.id,
            eventType: event.type,
            ...(error instanceof EventValidationError ? { problems: error.problems } : {}),
          },
          'Event telemetry: an event failed the event contract and was not exported'
        );
      }
    },

    forceFlush: () => processor.forceFlush(),

    async shutdown() {
      const left = await processor.close();
      if (left > 0) {
        log.warn(
          { records: left },
          'Event telemetry: records left unexported at shutdown, the collector did not answer in time'
        );
      }
    },
  };
}
