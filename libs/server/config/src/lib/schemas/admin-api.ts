import { z } from 'zod';

/**
 * The admin API's listener (ADR-019 Decisions 7 and 8, issue #511).
 *
 * The admin API runs on its own internal listener, a second HTTP server beside
 * the public one, on a process that holds the `admin` service role. It binds
 * to loopback by default, so a single deployment does not expose it; a
 * distributed deployment binds it to its internal network. The listener grants
 * nothing for a caller's network position: every call carries an admin token.
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */

/** Same parsing as `DPOP_ENABLED`: `'true'` / `'false'`, blank is unset. */
function strictBoolean(defaultValue: boolean) {
  return z
    .preprocess(
      (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
      z.enum(['true', 'false']).optional()
    )
    .transform((value) => (value === undefined ? defaultValue : value === 'true'));
}

/** Blank is unset, as `${VAR:-}` in a Compose file expands to. */
function blankAsUnset<T extends z.ZodType>(schema: T) {
  return z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    schema
  );
}

/** The address the admin listener binds to when `ADMIN_API_HOST` is unset: loopback only. */
export const DEFAULT_ADMIN_API_HOST = '127.0.0.1';

/** The port the admin listener binds to when `ADMIN_API_PORT` is unset. */
export const DEFAULT_ADMIN_API_PORT = 3002;

/**
 * Admin API listener environment configuration schema.
 */
export const adminApiEnvSchema = z.object({
  /**
   * Run the admin listener on a process that holds the `admin` role. On by
   * default; off, the process serves no admin API at all.
   */
  ADMIN_API_ENABLED: strictBoolean(true),
  /** The address the admin listener binds to. Loopback by default. */
  ADMIN_API_HOST: blankAsUnset(z.string().trim().min(1).default(DEFAULT_ADMIN_API_HOST)),
  /** The TCP port the admin listener binds to. */
  ADMIN_API_PORT: blankAsUnset(
    z.coerce.number().int().min(1).max(65535).default(DEFAULT_ADMIN_API_PORT)
  ),
});

export type AdminApiEnv = z.infer<typeof adminApiEnvSchema>;
