import { vi } from 'vitest';

// Every OTLP exporter the module creates is counted; none is real.
const exporters = vi.hoisted(() => ({ created: 0 }));
vi.mock('@opentelemetry/exporter-logs-otlp-http', () => ({
  OTLPLogExporter: class {
    constructor() {
      exporters.created += 1;
    }
    export(_logs: unknown, done: (result: { code: number }) => void) {
      done({ code: 0 });
    }
    shutdown() {
      return Promise.resolve();
    }
    forceFlush() {
      return Promise.resolve();
    }
  },
}));

import { createRequire } from 'node:module';

import { SeverityNumber } from '@opentelemetry/api-logs';
import { InMemoryLogRecordExporter } from '@opentelemetry/sdk-logs';
import type { EventEnvelope } from '@qauth-labs/shared-events';
import type { FastifyBaseLogger } from 'fastify';
import { Registry } from 'prom-client';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  createEventTelemetry,
  EVENT_LOGGER_NAME,
  eventTelemetrySettings,
  OTLP_DEFAULT_TIMEOUT_MILLIS,
} from './event-telemetry';

/**
 * The OpenTelemetry log export of events (issue #541): off by default, and
 * then no exporter and no request; on, one record per event, built and
 * checked before it is queued.
 */

// The CommonJS module objects the exporter's transport would call, which a
// spy can wrap; an ESM namespace cannot be spied on.
const nodeRequire = createRequire(__filename);
const http = nodeRequire('node:http') as typeof import('node:http');
const https = nodeRequire('node:https') as typeof import('node:https');

const REALM_ID = '0192f1c4-1111-7000-8000-000000000001';
const USER_ID = '0192f1c4-4444-7000-8000-000000000004';

const SIGNED_IN: EventEnvelope = {
  id: '0192f1c4-5555-7000-8000-000000000005',
  type: 'urn:qauth:event:user.signed_in:v1-rc.0',
  time: '2026-10-24T12:00:00.000Z',
  realm: REALM_ID,
  category: 'user',
  actor: { type: 'user', id: USER_ID },
  subject: { type: 'user', id: USER_ID },
  client: { id: 'portal' },
  request: { traceId: 'req-42' },
  data: { method: 'password' },
};

const ON = { enabled: true, serviceName: 'qauth-test', exporterTimeoutMillis: 1000 };
const OFF = { ...ON, enabled: false };

function fakeLog() {
  const log = { error: vi.fn(), warn: vi.fn() };
  return { log, asLogger: log as unknown as FastifyBaseLogger };
}

beforeEach(() => {
  exporters.created = 0;
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('eventTelemetrySettings', () => {
  it('is off unless the switch is on, and takes the logs timeout over the general one', () => {
    const base = { OTEL_EVENTS_ENABLED: false, OTEL_SERVICE_NAME: 'qauth-auth-server' };
    expect(eventTelemetrySettings(base)).toEqual({
      enabled: false,
      serviceName: 'qauth-auth-server',
      exporterTimeoutMillis: OTLP_DEFAULT_TIMEOUT_MILLIS,
    });
    expect(
      eventTelemetrySettings({ ...base, OTEL_EXPORTER_OTLP_TIMEOUT: '2000' }).exporterTimeoutMillis
    ).toBe(2000);
    expect(
      eventTelemetrySettings({
        ...base,
        OTEL_EXPORTER_OTLP_TIMEOUT: '2000',
        OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: '3000',
      }).exporterTimeoutMillis
    ).toBe(3000);
  });
});

describe('createEventTelemetry', () => {
  it('with the switch off, creates no exporter and makes no network call', async () => {
    const httpRequest = vi.spyOn(http, 'request');
    const httpsRequest = vi.spyOn(https, 'request');
    const fetchCall = vi.spyOn(globalThis, 'fetch');

    expect(createEventTelemetry(OFF, { log: fakeLog().asLogger })).toBeUndefined();
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(exporters.created).toBe(0);
    expect(httpRequest).not.toHaveBeenCalled();
    expect(httpsRequest).not.toHaveBeenCalled();
    expect(fetchCall).not.toHaveBeenCalled();
  });

  it('with the switch on, creates the OTLP exporter once', async () => {
    const telemetry = createEventTelemetry(ON, { log: fakeLog().asLogger });
    expect(exporters.created).toBe(1);
    await telemetry?.shutdown();
  });

  it('exports one record per event, with the service name and the events scope', async () => {
    const exporter = new InMemoryLogRecordExporter();
    const telemetry = createEventTelemetry(ON, { log: fakeLog().asLogger, exporter });
    if (telemetry === undefined) throw new Error('telemetry is on');

    telemetry.record(SIGNED_IN);
    expect(telemetry.queueLength).toBe(1);
    await telemetry.forceFlush();

    const [exported, ...rest] = exporter.getFinishedLogRecords();
    expect(rest).toEqual([]);
    expect(exported.body).toBe(JSON.stringify(SIGNED_IN));
    expect(exported.attributes).toMatchObject({
      'qauth.event.id': SIGNED_IN.id,
      'qauth.event.type': SIGNED_IN.type,
      'qauth.event.category': 'user',
      'qauth.realm': REALM_ID,
      'qauth.subject.id': USER_ID,
      'qauth.client.id': 'portal',
      'qauth.request.id': 'req-42',
    });
    expect(exported.severityNumber).toBe(SeverityNumber.INFO);
    expect(exported.resource.attributes['service.name']).toBe('qauth-test');
    expect(exported.instrumentationScope.name).toBe(EVENT_LOGGER_NAME);
    expect(telemetry.queueLength).toBe(0);
    await telemetry.shutdown();
  });

  it('refuses an event that fails the contract before it is queued, and logs why without the value', async () => {
    const exporter = new InMemoryLogRecordExporter();
    const { log, asLogger } = fakeLog();
    const telemetry = createEventTelemetry(ON, { log: asLogger, exporter });
    if (telemetry === undefined) throw new Error('telemetry is on');
    const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlLXZhbHVl';

    expect(() =>
      telemetry.record({ ...SIGNED_IN, request: { traceId: 'req-42', userAgent: token } })
    ).not.toThrow();
    await telemetry.forceFlush();

    expect(exporter.getFinishedLogRecords()).toEqual([]);
    expect(log.error).toHaveBeenCalledOnce();
    expect(log.error.mock.calls[0][0]).toMatchObject({
      eventId: SIGNED_IN.id,
      eventType: SIGNED_IN.type,
      problems: [expect.stringContaining('/request/userAgent')],
    });
    expect(JSON.stringify(log.error.mock.calls)).not.toContain(token);
    await telemetry.shutdown();
  });

  it('counts drops by reason on a counter the metrics registry serves', async () => {
    const telemetry = createEventTelemetry(ON, {
      log: fakeLog().asLogger,
      exporter: new InMemoryLogRecordExporter(),
      limits: { maxQueueSize: 1, scheduleDelayMillis: 60_000 },
    });
    if (telemetry === undefined) throw new Error('telemetry is on');
    const registry = new Registry();
    registry.registerMetric(telemetry.droppedRecords);

    telemetry.record(SIGNED_IN);
    telemetry.record({ ...SIGNED_IN, id: '0192f1c4-5555-7000-8000-000000000006' });

    const text = await registry.metrics();
    expect(text).toContain('qauth_events_telemetry_dropped_total{reason="queue_full"} 1');
    expect(text).toContain('qauth_events_telemetry_dropped_total{reason="export_failed"} 0');
    expect(telemetry.queueLength).toBe(1);
    expect(telemetry.maxQueueSize).toBe(1);
    await telemetry.shutdown();
  });

  it('warns at shutdown about the records a collector that never answers left behind', async () => {
    const { log, asLogger } = fakeLog();
    const telemetry = createEventTelemetry(ON, {
      log: asLogger,
      exporter: {
        export: () => undefined,
        shutdown: () => Promise.resolve(),
        forceFlush: () => Promise.resolve(),
      },
      limits: { scheduleDelayMillis: 0, shutdownTimeoutMillis: 50 },
    });
    if (telemetry === undefined) throw new Error('telemetry is on');

    telemetry.record(SIGNED_IN);
    await telemetry.shutdown();

    expect(log.warn).toHaveBeenCalledWith(
      { records: 1 },
      expect.stringContaining('left unexported at shutdown')
    );
  });
});
