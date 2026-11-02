import { z } from 'zod';

/**
 * The admin API's listener (ADR-019 Decisions 7 and 8, issue #511).
 *
 * The admin API runs on its own internal listener, a second HTTP server beside
 * the public one, on a process that holds the `admin` service role, once an
 * operator turns it on: it is off by default until the first admin operations
 * (#517) ship. It binds to loopback by default. The listener grants nothing
 * for a caller's network position: every call but the one for its OpenAPI
 * document carries a DPoP-bound admin token and a proof for it (#520), whose
 * `htu` is checked against `ADMIN_API_BASE_URL`.
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
 * What is wrong with `value` as `ADMIN_API_BASE_URL`, or `undefined`: it must
 * be an absolute `http` or `https` URL, with no user name or password, query
 * or fragment. A path is allowed, for a proxy that serves the listener under
 * one and strips it.
 */
function adminApiBaseUrlProblem(value: string): string | undefined {
  if (!URL.canParse(value)) return 'ADMIN_API_BASE_URL must be an absolute http or https URL';
  const url = new URL(value);
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return 'ADMIN_API_BASE_URL must be an absolute http or https URL';
  }
  if (url.username !== '' || url.password !== '') {
    return 'ADMIN_API_BASE_URL must not carry a user name or a password';
  }
  if (value.includes('?') || value.includes('#')) {
    return 'ADMIN_API_BASE_URL must not carry a query or a fragment';
  }
  return undefined;
}

/** `value` without the slashes it ends with, as the DPoP plugin joins a base URL and a path. */
function withoutTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value[end - 1] === '/') end -= 1;
  return value.slice(0, end);
}

/**
 * Admin API listener environment configuration schema.
 */
export const adminApiEnvSchema = z.object({
  /**
   * Run the admin listener on a process that holds the `admin` role. Off by
   * default until #517 ships; off, the process serves no admin API at all.
   */
  ADMIN_API_ENABLED: strictBoolean(false),
  /** The address the admin listener binds to. Loopback by default. */
  ADMIN_API_HOST: blankAsUnset(z.string().trim().min(1).default(DEFAULT_ADMIN_API_HOST)),
  /** The TCP port the admin listener binds to. */
  ADMIN_API_PORT: blankAsUnset(
    z.coerce.number().int().min(1).max(65535).default(DEFAULT_ADMIN_API_PORT)
  ),
  /**
   * The URL clients call the admin listener at (#520), without a trailing
   * slash. A DPoP proof's `htu` must be this URL followed by the request's
   * path; it is never built from the request. Required where the listener
   * runs: the auth server's schema checks that, as it knows the roles.
   */
  ADMIN_API_BASE_URL: blankAsUnset(
    z
      .string()
      .trim()
      .superRefine((value, ctx) => {
        const problem = adminApiBaseUrlProblem(value);
        if (problem !== undefined) ctx.addIssue({ code: 'custom', message: problem });
      })
      .transform(withoutTrailingSlashes)
      .optional()
  ),
});

export type AdminApiEnv = z.infer<typeof adminApiEnvSchema>;
