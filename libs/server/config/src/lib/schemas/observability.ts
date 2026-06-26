import { z } from 'zod';

/**
 * Observability environment configuration schema.
 *
 * Covers structured logging presentation, request-id propagation, the Prometheus
 * metrics endpoint, and failed-login throttling/lockout (QAuth §3.1.12 / §3.3).
 * `LOG_LEVEL` itself lives on the base schema and is honoured by the pino logger.
 */
export const observabilityEnvSchema = z.object({
  /**
   * Pretty-print logs via `pino-pretty` (human-readable, colourised).
   * Intended for local development only — production should emit JSON for log
   * shippers. Defaults to off; enable with `LOG_PRETTY=true`.
   */
  LOG_PRETTY: z
    .enum(['true', 'false', '1', '0'])
    .default('false')
    .transform((val) => val === 'true' || val === '1'),

  /**
   * Inbound/outbound HTTP header used to carry the request id. An incoming
   * value is propagated onto the request-scoped logger and echoed back on the
   * response so a single request can be traced end to end.
   */
  REQUEST_ID_HEADER: z.string().min(1).default('x-request-id'),

  /**
   * Enable the Prometheus `GET /metrics` endpoint. Defaults to on; set to
   * `false` to suppress the route (e.g. when metrics are scraped out of band).
   */
  METRICS_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('true')
    .transform((val) => val === 'true' || val === '1'),

  /**
   * Enable failed-login throttling/lockout (QAuth §3.1.12). When disabled the
   * login route still logs failures (§3.1 #125) but never blocks. Defaults to
   * on.
   */
  FAILED_LOGIN_TRACKING_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('true')
    .transform((val) => val === 'true' || val === '1'),

  /**
   * Number of failed login attempts (per identifier) within the window before
   * the identifier is temporarily locked out.
   */
  FAILED_LOGIN_MAX_ATTEMPTS: z.coerce.number().int().min(1).default(5),

  /**
   * Sliding window, in seconds, over which failed attempts are counted. The
   * counter key expires after this window with no further failures, giving a
   * natural decay/reset.
   */
  FAILED_LOGIN_WINDOW: z.coerce.number().int().min(1).default(900),

  /**
   * Lockout duration in seconds once `FAILED_LOGIN_MAX_ATTEMPTS` is reached.
   * During the lockout, login attempts for the identifier are rejected before
   * any credential verification.
   */
  FAILED_LOGIN_LOCKOUT_DURATION: z.coerce.number().int().min(1).default(900),
});

/**
 * Observability environment configuration type.
 */
export type ObservabilityEnv = z.infer<typeof observabilityEnvSchema>;
