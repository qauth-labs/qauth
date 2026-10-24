import { z } from 'zod';

/**
 * The OpenTelemetry log export of events (ADR-018 §3, issue #541): its
 * switch, its `service.name`, and the standard OTLP exporter variables of the
 * OpenTelemetry specification, logs signal.
 *
 * The OpenTelemetry exporter reads the `OTEL_EXPORTER_OTLP_*` variables from
 * the environment itself, with their standard meaning: a `LOGS_` variable
 * wins over the general one, `/v1/logs` is appended to the general endpoint
 * and not to the logs one, and the two header lists are merged. This schema
 * checks them so that a malformed value refuses the boot. The exporter would
 * otherwise ignore it without a word and fall back to its default. Blank
 * counts as unset, as it does for the exporter.
 *
 * A plain `z.object` with per-field rules, so the auth server can spread its
 * `.shape`.
 */

/** Blank is unset, as the OpenTelemetry SDK reads a variable. */
function unsetWhenBlank<T extends z.ZodType>(schema: T) {
  return z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    schema.optional()
  );
}

/** An OTLP/HTTP endpoint: an `http` or `https` URL. */
const otlpEndpoint = (name: string) =>
  unsetWhenBlank(z.url({ protocol: /^https?$/, error: `${name} must be an http or https URL` }));

/** An HTTP header name: an RFC 9110 token. */
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;

/**
 * Whether `value` is an OTLP header list: `name=value` pairs, comma-separated,
 * each part URL-encoded, as the OpenTelemetry specification writes it. A
 * decoded value may not hold a line break, which would split the header.
 */
function isHeaderList(value: string): boolean {
  return value
    .split(',')
    .filter((entry) => entry.trim() !== '')
    .every((entry) => {
      const separator = entry.indexOf('=');
      if (separator <= 0 || entry.includes(';')) return false;
      try {
        const name = decodeURIComponent(entry.slice(0, separator).trim());
        const headerValue = decodeURIComponent(entry.slice(separator + 1).trim());
        return HEADER_NAME.test(name) && headerValue !== '' && !/[\r\n\0]/.test(headerValue);
      } catch {
        return false;
      }
    });
}

/**
 * An OTLP header list. The values often hold a collector's API key, so the
 * error names the rule and never the value.
 */
const otlpHeaders = (name: string) =>
  unsetWhenBlank(
    z
      .string()
      .refine(isHeaderList, `${name} must be name=value pairs, comma-separated and URL-encoded`)
  );

/** An export timeout in milliseconds, a positive integer. */
const otlpTimeout = (name: string) =>
  unsetWhenBlank(
    z.coerce
      .number()
      .int(`${name} must be a whole number of milliseconds`)
      .positive(`${name} must be greater than 0`)
  );

/** `gzip` or `none`, the two the OTLP/HTTP exporter supports. */
const otlpCompression = () => unsetWhenBlank(z.enum(['gzip', 'none']));

/** A path to a PEM file the exporter reads at boot. */
const otlpPemPath = () => unsetWhenBlank(z.string());

export const eventTelemetryEnvSchema = z.object({
  /**
   * Export every event as an OpenTelemetry log record. Off by default: no
   * exporter is created and nothing is sent.
   */
  OTEL_EVENTS_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('false')
    .transform((val) => val === 'true' || val === '1'),

  /** The `service.name` resource attribute of every exported record. */
  OTEL_SERVICE_NAME: z.string().trim().min(1).max(255).default('qauth-auth-server'),

  /** The collector's base URL; `/v1/logs` is appended. */
  OTEL_EXPORTER_OTLP_ENDPOINT: otlpEndpoint('OTEL_EXPORTER_OTLP_ENDPOINT'),
  /** The full URL logs are sent to, used as it is. Wins over the base URL. */
  OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: otlpEndpoint('OTEL_EXPORTER_OTLP_LOGS_ENDPOINT'),

  /** Headers sent with every export, such as the collector's API key. */
  OTEL_EXPORTER_OTLP_HEADERS: otlpHeaders('OTEL_EXPORTER_OTLP_HEADERS'),
  /** Headers sent with every log export; merged over the general list. */
  OTEL_EXPORTER_OTLP_LOGS_HEADERS: otlpHeaders('OTEL_EXPORTER_OTLP_LOGS_HEADERS'),

  /** How long one export may take, retries included, in milliseconds. */
  OTEL_EXPORTER_OTLP_TIMEOUT: otlpTimeout('OTEL_EXPORTER_OTLP_TIMEOUT'),
  /** The same for log exports; wins over the general timeout. */
  OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: otlpTimeout('OTEL_EXPORTER_OTLP_LOGS_TIMEOUT'),

  /** `gzip` or `none`. */
  OTEL_EXPORTER_OTLP_COMPRESSION: otlpCompression(),
  /** The same for log exports; wins over the general setting. */
  OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: otlpCompression(),

  /** A PEM file of the CA certificates that verify the collector's TLS certificate. */
  OTEL_EXPORTER_OTLP_CERTIFICATE: otlpPemPath(),
  /** The same for log exports; wins over the general file. */
  OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE: otlpPemPath(),
  /** A PEM file of the client certificate chain, for a collector that asks for mutual TLS. */
  OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE: otlpPemPath(),
  /** The same for log exports; wins over the general file. */
  OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE: otlpPemPath(),
  /** A PEM file of the client certificate's private key. */
  OTEL_EXPORTER_OTLP_CLIENT_KEY: otlpPemPath(),
  /** The same for log exports; wins over the general file. */
  OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY: otlpPemPath(),
});

/** Event telemetry environment configuration type. */
export type EventTelemetryEnv = z.infer<typeof eventTelemetryEnvSchema>;
