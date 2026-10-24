import { defineKeys } from '../types';

/** The OpenTelemetry default the exporter applies when a variable is unset. */
const OTEL_DEFAULT = (value: string) => ({ computed: `${value}, the OpenTelemetry default` });

/** For a `LOGS_` variable: the general variable's value when that is set. */
const GENERAL = (name: string, fallback: string) => ({
  computed: `\`${name}\`, else ${fallback}`,
});

/**
 * The OpenTelemetry log export of events (ADR-018 §3, issue #541): the keys of
 * `eventTelemetryEnvSchema`.
 *
 * All `advanced` while the export is new: the names of the standard
 * `OTEL_*` variables are the OpenTelemetry specification's and will not
 * change, but which of them QAuth reads may.
 */
export const EVENT_TELEMETRY_KEYS = defineKeys([
  {
    name: 'OTEL_EVENTS_ENABLED',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: 'false',
    since: '0.2.0',
    docs: 'Send every event as an OpenTelemetry log record to the collector the `OTEL_EXPORTER_OTLP_*` keys name, as telemetry without a delivery guarantee; only then are those keys checked at boot.',
  },
  {
    name: 'OTEL_SERVICE_NAME',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: 'qauth-auth-server',
    since: '0.2.0',
    docs: 'The `service.name` resource attribute of every exported event record.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_ENDPOINT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: OTEL_DEFAULT('`http://localhost:4318`'),
    since: '0.2.0',
    docs: "The collector's OTLP/HTTP base URL, to which `/v1/logs` is appended.",
  },
  {
    name: 'OTEL_EXPORTER_OTLP_LOGS_ENDPOINT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: { computed: '`OTEL_EXPORTER_OTLP_ENDPOINT` with `/v1/logs` appended' },
    since: '0.2.0',
    docs: 'The full URL event records are sent to, used as it is and in place of `OTEL_EXPORTER_OTLP_ENDPOINT`.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_HEADERS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    secret: true,
    default: null,
    since: '0.2.0',
    docs: "Headers sent with every export, such as the collector's API key, as URL-encoded `name=value` pairs, comma-separated.",
  },
  {
    name: 'OTEL_EXPORTER_OTLP_LOGS_HEADERS',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    secret: true,
    default: null,
    since: '0.2.0',
    docs: 'Headers sent with every event export, in the same form, merged over `OTEL_EXPORTER_OTLP_HEADERS`.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_TIMEOUT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: OTEL_DEFAULT('`10000`'),
    since: '0.2.0',
    docs: 'How long one export may take, its retries included, in milliseconds, at most an hour.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_LOGS_TIMEOUT',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: GENERAL('OTEL_EXPORTER_OTLP_TIMEOUT', '`10000`'),
    since: '0.2.0',
    docs: 'How long one event export may take, in milliseconds, in place of `OTEL_EXPORTER_OTLP_TIMEOUT`.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_COMPRESSION',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: OTEL_DEFAULT('`none`'),
    since: '0.2.0',
    docs: 'How export requests are compressed, `gzip` or `none`.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_LOGS_COMPRESSION',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: GENERAL('OTEL_EXPORTER_OTLP_COMPRESSION', '`none`'),
    since: '0.2.0',
    docs: 'How event export requests are compressed, in place of `OTEL_EXPORTER_OTLP_COMPRESSION`.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_CERTIFICATE',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: { computed: "Node's own CA certificates" },
    since: '0.2.0',
    docs: "A PEM file of the CA certificates that verify the collector's TLS certificate.",
  },
  {
    name: 'OTEL_EXPORTER_OTLP_LOGS_CERTIFICATE',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: GENERAL('OTEL_EXPORTER_OTLP_CERTIFICATE', "Node's own CA certificates"),
    since: '0.2.0',
    docs: 'The CA certificate file for event exports, in place of `OTEL_EXPORTER_OTLP_CERTIFICATE`.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: null,
    since: '0.2.0',
    docs: 'A PEM file of the client certificate chain, for a collector that asks for mutual TLS.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_LOGS_CLIENT_CERTIFICATE',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: GENERAL('OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE', 'none'),
    since: '0.2.0',
    docs: 'The client certificate file for event exports, in place of `OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE`.',
  },
  {
    name: 'OTEL_EXPORTER_OTLP_CLIENT_KEY',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: null,
    since: '0.2.0',
    docs: "A PEM file of the client certificate's private key, for a collector that asks for mutual TLS.",
  },
  {
    name: 'OTEL_EXPORTER_OTLP_LOGS_CLIENT_KEY',
    tier: 'advanced',
    role: 'deployment',
    owner: 'observability',
    default: GENERAL('OTEL_EXPORTER_OTLP_CLIENT_KEY', 'none'),
    since: '0.2.0',
    docs: 'The client key file for event exports, in place of `OTEL_EXPORTER_OTLP_CLIENT_KEY`.',
  },
]);
