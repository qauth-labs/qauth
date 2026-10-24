import { describe, expect, it } from 'vitest';

import { eventTelemetryEnvSchema } from './event-telemetry';

/**
 * The OpenTelemetry log export's settings (issue #541). The exporter reads
 * the `OTEL_EXPORTER_OTLP_*` variables itself and ignores a malformed one
 * without a word; this schema refuses it at boot instead.
 */

/** The boot errors for `env`, as the operator reads them. */
function bootErrors(env: Record<string, string>): string[] {
  const result = eventTelemetryEnvSchema.safeParse(env);
  if (result.success) return [];
  return result.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`);
}

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
    expect(eventTelemetryEnvSchema.parse({ OTEL_EVENTS_ENABLED: 'true' }).OTEL_EVENTS_ENABLED).toBe(
      true
    );
    expect(eventTelemetryEnvSchema.parse({ OTEL_EVENTS_ENABLED: '1' }).OTEL_EVENTS_ENABLED).toBe(
      true
    );
    expect(eventTelemetryEnvSchema.parse({ OTEL_EVENTS_ENABLED: '0' }).OTEL_EVENTS_ENABLED).toBe(
      false
    );
    expect(bootErrors({ OTEL_EVENTS_ENABLED: 'yes' })).toHaveLength(1);
  });

  it('takes a service name and refuses a blank one', () => {
    expect(
      eventTelemetryEnvSchema.parse({ OTEL_SERVICE_NAME: 'auth-eu-1' }).OTEL_SERVICE_NAME
    ).toBe('auth-eu-1');
    expect(bootErrors({ OTEL_SERVICE_NAME: '   ' })).toHaveLength(1);
  });

  it('takes http and https endpoints and refuses any other URL or a non-URL', () => {
    const parsed = eventTelemetryEnvSchema.parse({
      OTEL_EXPORTER_OTLP_ENDPOINT: 'http://otel-collector:4318',
      OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: 'https://collector.internal/v1/logs',
    });
    expect(parsed.OTEL_EXPORTER_OTLP_ENDPOINT).toBe('http://otel-collector:4318');
    expect(parsed.OTEL_EXPORTER_OTLP_LOGS_ENDPOINT).toBe('https://collector.internal/v1/logs');

    expect(bootErrors({ OTEL_EXPORTER_OTLP_ENDPOINT: 'grpc://otel-collector:4317' })).toEqual([
      'OTEL_EXPORTER_OTLP_ENDPOINT: OTEL_EXPORTER_OTLP_ENDPOINT must be an http or https URL',
    ]);
    expect(bootErrors({ OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: 'otel-collector:4318' })).toHaveLength(1);
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

  it('takes a header list of URL-encoded name=value pairs', () => {
    const headers = 'x-api-key=abc%3D%3D,Authorization=Basic%20dXNlcjpwYXNz';
    expect(
      eventTelemetryEnvSchema.parse({ OTEL_EXPORTER_OTLP_HEADERS: headers })
        .OTEL_EXPORTER_OTLP_HEADERS
    ).toBe(headers);
  });

  it.each([
    ['an entry without =', 'x-api-key'],
    ['an empty name', '=s3cr3t'],
    ['an empty value', 'x-api-key='],
    ['a name that is not a header token', 'x api key=value'],
    ['metadata, which OTLP headers do not take', 'x-api-key=value;meta'],
    ['a value that decodes to a line break', 'x-api-key=a%0D%0AInjected: yes'],
    ['a value that does not decode', 'x-api-key=%E0%A4%A'],
  ])('refuses a header list with %s, naming the rule and never the value', (_case, headers) => {
    const errors = bootErrors({ OTEL_EXPORTER_OTLP_LOGS_HEADERS: headers });
    expect(errors).toEqual([
      'OTEL_EXPORTER_OTLP_LOGS_HEADERS: OTEL_EXPORTER_OTLP_LOGS_HEADERS must be name=value pairs, comma-separated and URL-encoded',
    ]);
    expect(errors.join()).not.toContain(headers);
  });

  it('takes a timeout in whole milliseconds above 0', () => {
    expect(
      eventTelemetryEnvSchema.parse({ OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: '2500' })
        .OTEL_EXPORTER_OTLP_LOGS_TIMEOUT
    ).toBe(2500);
    expect(bootErrors({ OTEL_EXPORTER_OTLP_TIMEOUT: '0' })).toHaveLength(1);
    expect(bootErrors({ OTEL_EXPORTER_OTLP_TIMEOUT: '1.5' })).toHaveLength(1);
    expect(bootErrors({ OTEL_EXPORTER_OTLP_TIMEOUT: 'ten' })).toHaveLength(1);
  });

  it('takes gzip or none as the compression', () => {
    expect(
      eventTelemetryEnvSchema.parse({ OTEL_EXPORTER_OTLP_COMPRESSION: 'gzip' })
        .OTEL_EXPORTER_OTLP_COMPRESSION
    ).toBe('gzip');
    expect(bootErrors({ OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: 'zstd' })).toHaveLength(1);
  });
});
