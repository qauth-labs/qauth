import { randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createServer as createTcpServer, type Socket } from 'node:net';

import { requireDockerOrSkip } from '@qauth-labs/shared-testing';
import type { FastifyInstance } from 'fastify';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';

import {
  baseEnvironment,
  bootAuthServer,
  type BootedAuthServer,
  E2E_PASSWORD,
  type E2eInfrastructure,
  generateJwtPem,
  type PemKeyPair,
  registerPasswordAccount,
  REQUIRED_TEST_ENVIRONMENT,
  resetE2eState,
  startE2eInfrastructure,
} from '../testing/e2e-harness';

/**
 * EVENTS AS OPENTELEMETRY LOG RECORDS (#541, ADR-018 §3).
 *
 * On the real server, Postgres and Redis: with an OTLP/HTTP receiver in this
 * process, every event the server commits arrives as one log record with the
 * event's attributes; with a collector that never answers, or one nobody
 * listens for, requests are answered as before, the queue stays within its
 * cap and the drop counter rises; and with the switch off nothing is wired
 * at all.
 *
 * Locally the suite skips when no Docker daemon is reachable; on CI it fails
 * (`requireDockerOrSkip`).
 */

const SIGNED_IN = 'urn:qauth:event:user.signed_in:v1-rc.0';
const SIGN_IN_FAILED = 'urn:qauth:event:user.sign_in_failed:v1-rc.0';

/** An OTLP attribute value, as the JSON encoding writes it. */
interface OtlpValue {
  stringValue?: string;
  intValue?: string | number;
  boolValue?: boolean;
}

interface OtlpKeyValue {
  key: string;
  value: OtlpValue;
}

/** One log record as a receiver gets it, its resource and scope flattened in. */
interface ReceivedRecord {
  readonly resource: Record<string, unknown>;
  readonly scope: string;
  readonly attributes: Record<string, unknown>;
  readonly body: string;
  readonly severityNumber: number;
  readonly severityText: string;
  readonly eventName: string;
  readonly traceId: string;
  readonly spanId: string;
}

const plain = (attributes: readonly OtlpKeyValue[] = []) =>
  Object.fromEntries(
    attributes.map(({ key, value }) => [
      key,
      value.stringValue ?? value.intValue ?? value.boolValue ?? value,
    ])
  );

/** An OTLP/HTTP logs receiver in this process: it keeps every record and answers 200. */
async function startOtlpReceiver(): Promise<{
  readonly url: string;
  readonly records: ReceivedRecord[];
  readonly paths: string[];
  close(): Promise<void>;
}> {
  const records: ReceivedRecord[] = [];
  const paths: string[] = [];
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => {
      paths.push(`${request.method} ${request.url} ${request.headers['content-type']}`);
      const payload = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      for (const resourceLogs of payload.resourceLogs ?? []) {
        const resource = plain(resourceLogs.resource?.attributes);
        for (const scopeLogs of resourceLogs.scopeLogs ?? []) {
          for (const logRecord of scopeLogs.logRecords ?? []) {
            records.push({
              resource,
              scope: scopeLogs.scope?.name,
              attributes: plain(logRecord.attributes),
              body: logRecord.body?.stringValue,
              severityNumber: logRecord.severityNumber,
              severityText: logRecord.severityText,
              eventName: logRecord.eventName,
              traceId: logRecord.traceId ?? '',
              spanId: logRecord.spanId ?? '',
            });
          }
        }
      }
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{}');
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('receiver has no port');
  return {
    url: `http://127.0.0.1:${address.port}`,
    records,
    paths,
    close: () => new Promise((resolve) => server.close(() => resolve())),
  };
}

/** A collector that accepts the connection and never answers: every export hangs. */
async function startBlackHole(): Promise<{ readonly port: number; close(): Promise<void> }> {
  const sockets = new Set<Socket>();
  const server = createTcpServer((socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.resume();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('black hole has no port');
  return {
    port: address.port,
    close: () =>
      new Promise((resolve) => {
        for (const socket of sockets) socket.destroy();
        server.close(() => resolve());
      }),
  };
}

/** A port nothing listens on: every export is refused at once. */
async function closedPort(): Promise<number> {
  const server = createTcpServer();
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no port');
  await new Promise<void>((resolve) => server.close(() => resolve()));
  return address.port;
}

/** A row of `events`, the members a log record repeats. */
interface StoredRow {
  id: string;
  type: string;
  realm_id: string;
  category: string;
  subject_id: string | null;
  client_id: string | null;
  request_id: string | null;
  data: Record<string, unknown>;
}

async function storedEvents(app: FastifyInstance): Promise<StoredRow[]> {
  const { rows } = await app.dbPool.query<StoredRow>(
    `SELECT id, type, realm_id, category, subject_id, client_id, request_id, data
     FROM events ORDER BY xid::text::numeric, seq`
  );
  return rows;
}

/** The value of one series of the drop counter on `/metrics`. */
async function dropped(app: FastifyInstance, reason: string): Promise<number> {
  const response = await app.inject({ method: 'GET', url: '/metrics' });
  expect(response.statusCode).toBe(200);
  const match = new RegExp(
    `^qauth_events_telemetry_dropped_total\\{reason="${reason}"[^}]*\\} (\\d+)$`,
    'm'
  ).exec(response.body);
  if (match === null) throw new Error(`no ${reason} series on /metrics`);
  return Number(match[1]);
}

/** Wait until `check` holds, or fail after `timeoutMillis`. */
async function eventually(check: () => Promise<boolean>, timeoutMillis: number): Promise<void> {
  const deadline = Date.now() + timeoutMillis;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error(`not true within ${timeoutMillis} ms`);
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
}

function telemetryOf(app: FastifyInstance) {
  if (app.eventTelemetry === undefined) throw new Error('the event telemetry is off');
  return app.eventTelemetry;
}

async function signIn(app: FastifyInstance, email: string, password = E2E_PASSWORD) {
  return app.inject({ method: 'POST', url: '/auth/login', payload: { email, password } });
}

describe('events as OpenTelemetry log records (real containers)', () => {
  let infra: E2eInfrastructure | undefined;
  let jwt: PemKeyPair | undefined;
  let dockerUp = false;
  let booted: BootedAuthServer | undefined;
  const cleanups: Array<() => Promise<void>> = [];

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    infra = await startE2eInfrastructure();
    jwt = await generateJwtPem();
  }, 240_000);

  afterAll(async () => {
    await infra?.teardown();
  });

  beforeEach((ctx) => {
    if (!dockerUp) ctx.skip();
  });

  afterEach(async () => {
    await booted?.close();
    booted = undefined;
    for (const cleanup of cleanups.splice(0)) await cleanup();
  });

  function environment(extra: Record<string, string>): Record<string, string> {
    if (infra === undefined || jwt === undefined) throw new Error('infrastructure not started');
    return { ...baseEnvironment(infra, jwt), ...extra };
  }

  it('one emitted event produces one log record with the expected attributes', async () => {
    const receiver = await startOtlpReceiver();
    cleanups.push(() => receiver.close());
    booted = await bootAuthServer(
      environment({
        OTEL_EVENTS_ENABLED: 'true',
        OTEL_EXPORTER_OTLP_ENDPOINT: receiver.url,
        OTEL_SERVICE_NAME: 'qauth-e2e',
      }),
      { eventTelemetryLimits: { scheduleDelayMillis: 10 } }
    );
    const { app } = booted;
    await resetE2eState(app);
    await telemetryOf(app).forceFlush();
    receiver.records.length = 0;

    const email = `otel-${randomUUID()}@example.com`;
    const userId = await registerPasswordAccount(app, email);
    const login = await signIn(app, email);
    expect(login.statusCode).toBe(200);
    const refused = await signIn(app, email, 'not-the-password-of-this-account');
    expect(refused.statusCode).toBe(401);
    await telemetryOf(app).forceFlush();

    // One record per committed event, no more and no fewer.
    const stored = await storedEvents(app);
    expect(stored.map((event) => event.type)).toEqual(
      expect.arrayContaining([SIGNED_IN, SIGN_IN_FAILED])
    );
    const exportedIds = receiver.records.map((record) => record.attributes['qauth.event.id']);
    expect(new Set(exportedIds).size).toBe(exportedIds.length);
    expect([...exportedIds].sort()).toEqual(stored.map((event) => event.id).sort());
    expect(receiver.paths[0]).toBe('POST /v1/logs application/json');

    const signedIn = stored.find((event) => event.type === SIGNED_IN);
    if (signedIn === undefined) throw new Error('no sign-in event was stored');
    const record = receiver.records.find((r) => r.attributes['qauth.event.id'] === signedIn.id);
    if (record === undefined) throw new Error('the sign-in event was not exported');
    expect(signedIn.subject_id).toBe(userId);
    expect(signedIn.client_id).not.toBeNull();
    expect(signedIn.request_id).toBe(login.headers['x-request-id']);
    expect(record.attributes).toEqual({
      'qauth.event.id': signedIn.id,
      'qauth.event.type': SIGNED_IN,
      'qauth.event.category': 'user',
      'qauth.realm': signedIn.realm_id,
      'qauth.subject.id': userId,
      'qauth.client.id': signedIn.client_id,
      // No span is active in this process, so the request id stands in.
      'qauth.request.id': login.headers['x-request-id'],
    });
    expect(record.traceId).toBe('');
    expect(record.spanId).toBe('');
    expect(record.severityNumber).toBe(9);
    expect(record.severityText).toBe('info');
    expect(record.eventName).toBe(SIGNED_IN);
    expect(record.scope).toBe('qauth.events');
    expect(record.resource['service.name']).toBe('qauth-e2e');
    expect(JSON.parse(record.body)).toMatchObject({
      id: signedIn.id,
      type: SIGNED_IN,
      realm: signedIn.realm_id,
      category: 'user',
      subject: { type: 'user', id: userId },
      client: { id: signedIn.client_id },
      request: { traceId: login.headers['x-request-id'] },
      data: signedIn.data,
    });

    const failed = receiver.records.find(
      (r) => r.attributes['qauth.event.type'] === SIGN_IN_FAILED
    );
    expect(failed?.severityNumber).toBe(13);
    expect(failed?.severityText).toBe('warning');
    expect(await dropped(app, 'queue_full')).toBe(0);
    expect(await dropped(app, 'export_failed')).toBe(0);
  });

  it('with a collector that never answers, requests still succeed, the queue stays within its cap and the drop counter rises', async () => {
    const hole = await startBlackHole();
    cleanups.push(() => hole.close());
    const exporterTimeout = 4000;
    booted = await bootAuthServer(
      environment({
        OTEL_EVENTS_ENABLED: 'true',
        OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: `http://127.0.0.1:${hole.port}/v1/logs`,
        OTEL_EXPORTER_OTLP_TIMEOUT: String(exporterTimeout),
      }),
      {
        eventTelemetryLimits: {
          maxQueueSize: 4,
          maxExportBatchSize: 2,
          scheduleDelayMillis: 10,
          shutdownTimeoutMillis: 200,
        },
      }
    );
    const { app } = booted;
    await resetE2eState(app);
    const telemetry = telemetryOf(app);
    expect(telemetry.maxQueueSize).toBe(4);

    // The registration's events go out first and their export hangs.
    const email = `otel-${randomUUID()}@example.com`;
    await registerPasswordAccount(app, email);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const started = Date.now();
      const login = await signIn(app, email);
      expect(login.statusCode).toBe(200);
      expect(Date.now() - started).toBeLessThan(exporterTimeout);
      expect(telemetry.queueLength).toBeLessThanOrEqual(4);
    }

    // A burst of events while the export is out: the queue keeps the newest four.
    const realmId = (await storedEvents(app))[0].realm_id;
    for (let n = 0; n < 20; n += 1) {
      await app.repositories.events.emitInOwnTransaction({
        type: SIGN_IN_FAILED,
        realm: realmId,
        actor: { type: 'user' },
        data: { method: 'password', reason: 'invalid_credentials' },
      });
      expect(telemetry.queueLength).toBeLessThanOrEqual(4);
    }
    expect(await dropped(app, 'queue_full')).toBeGreaterThanOrEqual(16);

    // The hung export reaches the exporter's timeout and its batch is counted.
    await eventually(async () => (await dropped(app, 'export_failed')) > 0, exporterTimeout * 3);
    expect(telemetry.queueLength).toBeLessThanOrEqual(4);
    // Every event is still in the store: the event API's route never depended on this one.
    expect((await storedEvents(app)).length).toBeGreaterThanOrEqual(24);
  }, 60_000);

  it('with nothing listening at the endpoint, requests still succeed and the refused batches are counted', async () => {
    const port = await closedPort();
    booted = await bootAuthServer(
      environment({
        OTEL_EVENTS_ENABLED: 'true',
        OTEL_EXPORTER_OTLP_ENDPOINT: `http://127.0.0.1:${port}`,
        OTEL_EXPORTER_OTLP_TIMEOUT: '1000',
      }),
      { eventTelemetryLimits: { scheduleDelayMillis: 10, shutdownTimeoutMillis: 200 } }
    );
    const { app } = booted;
    await resetE2eState(app);

    const email = `otel-${randomUUID()}@example.com`;
    await registerPasswordAccount(app, email);
    const login = await signIn(app, email);
    expect(login.statusCode).toBe(200);

    await eventually(async () => (await dropped(app, 'export_failed')) > 0, 10_000);
    expect(telemetryOf(app).queueLength).toBeLessThanOrEqual(telemetryOf(app).maxQueueSize);
  }, 30_000);

  it('with the switch off, nothing is wired: no export, no counter, the database untouched', async () => {
    booted = await bootAuthServer(environment({}));
    const { app } = booted;
    await resetE2eState(app);

    const email = `otel-${randomUUID()}@example.com`;
    await registerPasswordAccount(app, email);
    expect((await signIn(app, email)).statusCode).toBe(200);

    expect(app.eventTelemetry).toBeUndefined();
    expect(Object.hasOwn(app.db, 'transaction')).toBe(false);
    const metrics = await app.inject({ method: 'GET', url: '/metrics' });
    expect(metrics.body).not.toContain('qauth_events_telemetry_dropped_total');
    expect(REQUIRED_TEST_ENVIRONMENT['OTEL_EVENTS_ENABLED']).toBeUndefined();
  });
});
