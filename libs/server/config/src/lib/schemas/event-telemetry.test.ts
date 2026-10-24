import { describe, expect, it } from 'vitest';

import {
  eventTelemetryEnvSchema,
  OTLP_TIMEOUT_MAX_MILLIS,
  type OtlpExporterEnv,
  otlpExporterProblems,
  otlpLogsTimeoutMillis,
} from './event-telemetry';

/**
 * The OpenTelemetry log export's settings (issue #541). The exporter reads
 * the `OTEL_EXPORTER_OTLP_*` variables itself and ignores a malformed one
 * without a word; `otlpExporterProblems` finds it, and the auth server
 * refuses the boot on it when the export is on.
 */

/** The problems for `env`, as the operator reads them. */
const problems = (env: OtlpExporterEnv) =>
  otlpExporterProblems(env).map((problem) => `${problem.variable}: ${problem.message}`);

describe('eventTelemetryEnvSchema', () => {
  it('is off by default, with the auth server as the service name, and leaves the exporter to its defaults', () => {
    const parsed = eventTelemetryEnvSchema.parse({});
    expect(parsed.OTEL_EVENTS_ENABLED).toBe(false);
    expect(parsed.OTEL_SERVICE_NAME).toBe('qauth-auth-server');
    expect(parsed.OTEL_EXPORTER_OTLP_ENDPOINT).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_HEADERS).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_TIMEOUT).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_COMPRESSION).toBeUndefined();
  });

  it('takes the switch as true, false, 1 or 0, and refuses anything else', () => {
    const enabled = (value: string) =>
      eventTelemetryEnvSchema.parse({ OTEL_EVENTS_ENABLED: value }).OTEL_EVENTS_ENABLED;
    expect(enabled('true')).toBe(true);
    expect(enabled('1')).toBe(true);
    expect(enabled('0')).toBe(false);
    expect(eventTelemetryEnvSchema.safeParse({ OTEL_EVENTS_ENABLED: 'yes' }).success).toBe(false);
  });

  it('takes a service name and refuses a blank one', () => {
    expect(
      eventTelemetryEnvSchema.parse({ OTEL_SERVICE_NAME: 'auth-eu-1' }).OTEL_SERVICE_NAME
    ).toBe('auth-eu-1');
    expect(eventTelemetryEnvSchema.safeParse({ OTEL_SERVICE_NAME: '   ' }).success).toBe(false);
  });

  it('takes any exporter value as text, since another OpenTelemetry component may set it', () => {
    const parsed = eventTelemetryEnvSchema.parse({
      OTEL_EXPORTER_OTLP_HEADERS: 'x-api-key=abc;meta',
      OTEL_EXPORTER_OTLP_TIMEOUT: '1.5',
    });
    expect(parsed.OTEL_EXPORTER_OTLP_HEADERS).toBe('x-api-key=abc;meta');
    expect(parsed.OTEL_EXPORTER_OTLP_TIMEOUT).toBe('1.5');
  });

  it('reads a blank variable as unset, as the exporter does', () => {
    const parsed = eventTelemetryEnvSchema.parse({
      OTEL_EXPORTER_OTLP_ENDPOINT: '',
      OTEL_EXPORTER_OTLP_HEADERS: '  ',
      OTEL_EXPORTER_OTLP_TIMEOUT: '',
      OTEL_EXPORTER_OTLP_COMPRESSION: '',
      OTEL_EXPORTER_OTLP_CERTIFICATE: '',
    });
    expect(parsed.OTEL_EXPORTER_OTLP_ENDPOINT).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_HEADERS).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_TIMEOUT).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_COMPRESSION).toBeUndefined();
    expect(parsed.OTEL_EXPORTER_OTLP_CERTIFICATE).toBeUndefined();
  });
});

describe('otlpExporterProblems', () => {
  it('finds nothing when nothing is set, or every value is well formed', () => {
    expect(problems({})).toEqual([]);
    expect(
      problems({
        OTEL_EXPORTER_OTLP_ENDPOINT: 'http://otel-collector:4318',
        OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: 'https://collector.internal/v1/logs',
        OTEL_EXPORTER_OTLP_HEADERS: 'x-api-key=abc%3D%3D,Authorization=Basic%20dXNlcjpwYXNz',
        OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: '2500',
        OTEL_EXPORTER_OTLP_COMPRESSION: 'gzip',
        OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: 'none',
      })
    ).toEqual([]);
  });

  it('refuses an endpoint that is not an http or https URL', () => {
    expect(
      problems({
        OTEL_EXPORTER_OTLP_ENDPOINT: 'grpc://otel-collector:4317',
        OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: 'otel-collector:4318',
      })
    ).toEqual([
      'OTEL_EXPORTER_OTLP_ENDPOINT: OTEL_EXPORTER_OTLP_ENDPOINT must be an http or https URL',
      'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: OTEL_EXPORTER_OTLP_LOGS_ENDPOINT must be an http or https URL',
    ]);
  });

  it.each([
    ['an entry without =', 'x-api-key'],
    ['an empty name', '=s3cr3t'],
    ['an empty value', 'x-api-key='],
    ['a name that is not a header token', 'x api key=s3cr3t'],
    ['metadata, which OTLP headers do not take', 'x-api-key=s3cr3t;meta'],
    ['a value that decodes to a line break', 'x-api-key=a%0D%0AInjected: yes'],
    ['a value that does not decode', 'x-api-key=%E0%A4%A'],
  ])('refuses a header list with %s, naming the rule and never the value', (_case, headers) => {
    const found = problems({ OTEL_EXPORTER_OTLP_LOGS_HEADERS: headers });
    expect(found).toEqual([
      'OTEL_EXPORTER_OTLP_LOGS_HEADERS: OTEL_EXPORTER_OTLP_LOGS_HEADERS must be name=value pairs, comma-separated and URL-encoded',
    ]);
    expect(found.join()).not.toContain(headers);
  });

  it.each(['0', '1.5', 'ten', '-5', String(OTLP_TIMEOUT_MAX_MILLIS + 1)])(
    'refuses the timeout %s',
    (timeout) => {
      expect(problems({ OTEL_EXPORTER_OTLP_TIMEOUT: timeout })).toEqual([
        `OTEL_EXPORTER_OTLP_TIMEOUT: OTEL_EXPORTER_OTLP_TIMEOUT must be a whole number of milliseconds from 1 to ${OTLP_TIMEOUT_MAX_MILLIS}`,
      ]);
    }
  );

  it('refuses a compression other than gzip or none', () => {
    expect(problems({ OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: 'zstd' })).toEqual([
      'OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: OTEL_EXPORTER_OTLP_LOGS_COMPRESSION must be gzip or none',
    ]);
  });
});

describe('otlpLogsTimeoutMillis', () => {
  it('takes the logs timeout over the general one, and neither when malformed', () => {
    expect(otlpLogsTimeoutMillis({})).toBeUndefined();
    expect(otlpLogsTimeoutMillis({ OTEL_EXPORTER_OTLP_TIMEOUT: '2000' })).toBe(2000);
    expect(
      otlpLogsTimeoutMillis({
        OTEL_EXPORTER_OTLP_TIMEOUT: '2000',
        OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: '3000',
      })
    ).toBe(3000);
    expect(
      otlpLogsTimeoutMillis({
        OTEL_EXPORTER_OTLP_TIMEOUT: '2000',
        OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: 'soon',
      })
    ).toBe(2000);
  });
});
