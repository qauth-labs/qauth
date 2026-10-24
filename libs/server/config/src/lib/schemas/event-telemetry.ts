import { accessSync, constants, statSync } from 'node:fs';
import { resolve } from 'node:path';

import { z } from 'zod';

/**
 * The OpenTelemetry log export of events (ADR-018 §3, issue #541): its
 * switch, its `service.name`, and the standard OTLP exporter variables of the
 * OpenTelemetry specification, logs signal.
 *
 * The OpenTelemetry exporter reads the `OTEL_EXPORTER_OTLP_*` variables from
 * the environment itself, with their standard meaning: a `LOGS_` variable
 * wins over the general one, `/v1/logs` is appended to the general endpoint
 * and not to the logs one, and the two header lists are merged. Blank counts
 * as unset, as it does for the exporter.
 *
 * Those variables are process-wide, and another OpenTelemetry component the
 * operator runs in the same process may set them in a form the SDK accepts
 * and QAuth's check would not. So this schema takes them as text, and
 * {@link otlpExporterProblems} checks them; the auth server runs that check
 * only when `OTEL_EVENTS_ENABLED` is on, and then a malformed value refuses
 * the boot, which the exporter would otherwise ignore without a word.
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

/** An OTLP exporter variable, as text; {@link otlpExporterProblems} checks it. */
const otlpSetting = () => unsetWhenBlank(z.string());

export const eventTelemetryEnvSchema = z.object({
  /**
   * Export every event as an OpenTelemetry log record. Off by default: no
   * exporter is created and nothing is sent.
   */
  OTEL_EVENTS_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('false')
    .transform((val) => val === 'true' || val === '1'),

  /**
   * The `service.name` resource attribute of every exported record. A blank
   * value is unset, as for the exporter variables, so it takes the default
   * rather than refuse a boot that may not export at all.
   */
  OTEL_SERVICE_NAME: unsetWhenBlank(z.string().trim().min(1)).transform(
    (value) => value ?? 'qauth-auth-server'
  ),

  /** The collector's base URL; `/v1/logs` is appended. */
  OTEL_EXPORTER_OTLP_ENDPOINT: otlpSetting(),
  /** The full URL logs are sent to, used as it is. Wins over the base URL. */
  OTEL_EXPORTER_OTLP_LOGS_ENDPOINT: otlpSetting(),

  /** Headers sent with every export, such as the collector's API key. */
  OTEL_EXPORTER_OTLP_HEADERS: otlpSetting(),
  /** Headers sent with every log export; merged over the general list. */
  OTEL_EXPORTER_OTLP_LOGS_HEADERS: otlpSetting(),

  /** How long one export may take, retries included, in milliseconds. */
  OTEL_EXPORTER_OTLP_TIMEOUT: otlpSetting(),
  /** The same for log exports; wins over the general timeout. */
  OTEL_EXPORTER_OTLP_LOGS_TIMEOUT: otlpSetting(),

  /** `gzip` or `none`. */
  OTEL_EXPORTER_OTLP_COMPRESSION: otlpSetting(),
  /** The same for log exports; wins over the general setting. */
  OTEL_EXPORTER_OTLP_LOGS_COMPRESSION: otlpSetting(),

  /** A PEM file of the CA certificates that verify the collector's TLS certificate. */
  OTEL_EXPORTER_OTLP_CERTIFICATE: otlpSetting(),
  /** The same for log exports; wins over the general file. */
  OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE: otlpSetting(),
  /** A PEM file of the client certificate chain, for a collector that asks for mutual TLS. */
  OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE: otlpSetting(),
  /** The same for log exports; wins over the general file. */
  OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE: otlpSetting(),
  /** A PEM file of the client certificate's private key. */
  OTEL_EXPORTER_OTLP_CLIENT_KEY: otlpSetting(),
  /** The same for log exports; wins over the general file. */
  OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY: otlpSetting(),
});

/** Event telemetry environment configuration type. */
export type EventTelemetryEnv = z.infer<typeof eventTelemetryEnvSchema>;

/** The OTLP exporter variables {@link otlpExporterProblems} checks. */
export type OtlpExporterEnv = Partial<
  Pick<
    EventTelemetryEnv,
    | 'OTEL_EXPORTER_OTLP_ENDPOINT'
    | 'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT'
    | 'OTEL_EXPORTER_OTLP_HEADERS'
    | 'OTEL_EXPORTER_OTLP_LOGS_HEADERS'
    | 'OTEL_EXPORTER_OTLP_TIMEOUT'
    | 'OTEL_EXPORTER_OTLP_LOGS_TIMEOUT'
    | 'OTEL_EXPORTER_OTLP_COMPRESSION'
    | 'OTEL_EXPORTER_OTLP_LOGS_COMPRESSION'
    | 'OTEL_EXPORTER_OTLP_CERTIFICATE'
    | 'OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE'
    | 'OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE'
    | 'OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE'
    | 'OTEL_EXPORTER_OTLP_CLIENT_KEY'
    | 'OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY'
  >
>;

/**
 * The TLS files the exporter reads, each as its logs variable and the general
 * one: the logs variable wins, as the exporter takes it.
 */
const OTLP_TLS_FILES = [
  ['OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE', 'OTEL_EXPORTER_OTLP_CERTIFICATE'],
  ['OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE', 'OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE'],
  ['OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY', 'OTEL_EXPORTER_OTLP_CLIENT_KEY'],
] as const;

/** Whether `path`, resolved as the exporter resolves it, is a file this process can read. */
function isReadableFile(path: string): boolean {
  const resolved = resolve(process.cwd(), path);
  try {
    accessSync(resolved, constants.R_OK);
    return statSync(resolved).isFile();
  } catch {
    return false;
  }
}

/** The longest export timeout QAuth accepts: an hour, in milliseconds. */
export const OTLP_TIMEOUT_MAX_MILLIS = 3_600_000;

/** One malformed OTLP exporter variable, for the boot error. */
export interface OtlpExporterProblem {
  readonly variable: keyof OtlpExporterEnv;
  readonly message: string;
}

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

const httpUrl = z.url({ protocol: /^https?$/ });

/** A timeout in whole milliseconds, above 0 and at most an hour, or `undefined`. */
function timeoutMillis(value: string | undefined): number | undefined {
  if (value === undefined || !/^\d+$/.test(value.trim())) return undefined;
  const millis = Number(value.trim());
  return millis > 0 && millis <= OTLP_TIMEOUT_MAX_MILLIS ? millis : undefined;
}

/**
 * The malformed OTLP exporter variables, one problem each; empty when every
 * one that is set is well formed. A header list often holds the collector's
 * API key, so a problem names the rule and never the value.
 */
export function otlpExporterProblems(env: OtlpExporterEnv): OtlpExporterProblem[] {
  const problems: OtlpExporterProblem[] = [];
  const check = (
    variable: keyof OtlpExporterEnv,
    wellFormed: (value: string) => boolean,
    rule: string
  ) => {
    const value = env[variable];
    if (value !== undefined && !wellFormed(value)) {
      problems.push({ variable, message: `${variable} must be ${rule}` });
    }
  };
  for (const variable of [
    'OTEL_EXPORTER_OTLP_ENDPOINT',
    'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT',
  ] as const) {
    check(variable, (value) => httpUrl.safeParse(value).success, 'an http or https URL');
  }
  for (const variable of [
    'OTEL_EXPORTER_OTLP_HEADERS',
    'OTEL_EXPORTER_OTLP_LOGS_HEADERS',
  ] as const) {
    check(variable, isHeaderList, 'name=value pairs, comma-separated and URL-encoded');
  }
  for (const variable of [
    'OTEL_EXPORTER_OTLP_TIMEOUT',
    'OTEL_EXPORTER_OTLP_LOGS_TIMEOUT',
  ] as const) {
    check(
      variable,
      (value) => timeoutMillis(value) !== undefined,
      `a whole number of milliseconds from 1 to ${OTLP_TIMEOUT_MAX_MILLIS}`
    );
  }
  for (const variable of [
    'OTEL_EXPORTER_OTLP_COMPRESSION',
    'OTEL_EXPORTER_OTLP_LOGS_COMPRESSION',
  ] as const) {
    check(variable, (value) => value === 'gzip' || value === 'none', 'gzip or none');
  }
  // The exporter reads a TLS file it cannot open as unset, with a diagnostic
  // nothing prints. A CA file left unmounted would then make it trust the
  // public CAs in place of the operator's, so a file named must be readable.
  // The client certificate and its key only work together.
  const effective = (pair: (typeof OTLP_TLS_FILES)[number]) =>
    pair.find((variable) => env[variable] !== undefined);
  for (const pair of OTLP_TLS_FILES) {
    const variable = effective(pair);
    if (variable !== undefined) check(variable, isReadableFile, 'a file this process can read');
  }
  const certificate = effective(OTLP_TLS_FILES[1]);
  const key = effective(OTLP_TLS_FILES[2]);
  if ((certificate === undefined) !== (key === undefined)) {
    const [missing, given] =
      certificate === undefined
        ? (['OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE', key] as const)
        : (['OTEL_EXPORTER_OTLP_CLIENT_KEY', certificate] as const);
    problems.push({
      variable: missing,
      message: `${missing} (or its LOGS_ form) must be set with ${given}: a client certificate and its key work only together`,
    });
  }
  return problems;
}

/**
 * The log export's timeout as the exporter takes it: the logs variable when
 * it is well formed, else the general one, else `undefined` (the
 * OpenTelemetry default applies).
 */
export function otlpLogsTimeoutMillis(env: OtlpExporterEnv): number | undefined {
  return (
    timeoutMillis(env.OTEL_EXPORTER_OTLP_LOGS_TIMEOUT) ??
    timeoutMillis(env.OTEL_EXPORTER_OTLP_TIMEOUT)
  );
}
