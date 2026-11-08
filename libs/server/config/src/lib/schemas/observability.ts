import { z } from 'zod';

/**
 * The longest window, in seconds, over which failed logins may be counted: one
 * day. The bound came with the admin API's realm policy update (#517, decided
 * 2026-11-01), the first path that lets a realm admin set it: a window that
 * reaches back further keeps one identifier's failures counting for days.
 */
export const MAX_FAILED_LOGIN_WINDOW_SECONDS = 86_400;

/**
 * The longest lockout, in seconds, after repeated failed logins: one day. The
 * bound came with the admin API's realm policy update (#517, decided
 * 2026-11-01): a lockout is started by anyone who knows an identifier, so a
 * long one lets them keep its account out for as long as it lasts.
 */
export const MAX_FAILED_LOGIN_LOCKOUT_SECONDS = 86_400;

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
   * Enable the Prometheus metrics endpoint, `GET /internal/metrics` on the
   * internal listener (#500). Defaults to on, and then every process runs
   * the internal listener; set to `false` to serve no metrics.
   */
  METRICS_ENABLED: z
    .enum(['true', 'false', '1', '0'])
    .default('true')
    .transform((val) => val === 'true' || val === '1'),

  /**
   * Enable failed-login throttling/lockout (QAuth §3.1.12). When disabled the
   * login route still logs failures (§3.1 #125) but never blocks. Defaults to
   * on.
   *
   * This key and the three below seed a new realm's `bruteForce` policies
   * (#528). The auth server reads each realm's own policies from the realm
   * row; a later change of a key leaves a realm that has its policies as it is.
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
   * natural decay/reset. At most {@link MAX_FAILED_LOGIN_WINDOW_SECONDS}.
   */
  FAILED_LOGIN_WINDOW: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_FAILED_LOGIN_WINDOW_SECONDS)
    .default(900),

  /**
   * Lockout duration in seconds once `FAILED_LOGIN_MAX_ATTEMPTS` is reached.
   * During the lockout, login attempts for the identifier are rejected before
   * any credential verification. At most {@link MAX_FAILED_LOGIN_LOCKOUT_SECONDS}.
   */
  FAILED_LOGIN_LOCKOUT_DURATION: z.coerce
    .number()
    .int()
    .min(1)
    .max(MAX_FAILED_LOGIN_LOCKOUT_SECONDS)
    .default(900),
});

/**
 * Observability environment configuration type.
 */
export type ObservabilityEnv = z.infer<typeof observabilityEnvSchema>;
