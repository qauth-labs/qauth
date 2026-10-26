import { z } from 'zod';

/**
 * Service roles (ADR-019 Decision 8, issue #495): which parts of the auth
 * server this process runs.
 *
 * One codebase starts as one or more roles. A single deployment runs every
 * role in one process (`all`, the default), which is one trust domain. A
 * distributed deployment starts each role on its own nodes, so a node that
 * does not hold the signer holds no key:
 *
 * - `web`: the browser-session endpoints (the `browser` routes of #486);
 * - `api`: token, introspection, revocation, userinfo, registration,
 *   discovery, JWKS, the account and developer APIs and the legacy `/auth/*`
 *   routes;
 * - `admin`: the admin API and key operations, on the internal listener;
 * - `signer`: the signer and the key jobs; the only role that holds the KEK
 *   and the private keys;
 * - `delivery`: the event delivery reader.
 *
 * A plain `z.object`, so the auth server can spread its `.shape`.
 */

/** The roles a process can hold, in the order the server lists them. */
export const SERVICE_ROLE_NAMES = ['web', 'api', 'admin', 'signer', 'delivery'] as const;

/** One of {@link SERVICE_ROLE_NAMES}. */
export type ServiceRole = (typeof SERVICE_ROLE_NAMES)[number];

/** The `SERVICE_ROLES` value that names every role: a single process. */
export const ALL_SERVICE_ROLES = 'all';

/** Whether `value` is one of {@link SERVICE_ROLE_NAMES}. */
export function isServiceRole(value: string): value is ServiceRole {
  return (SERVICE_ROLE_NAMES as readonly string[]).includes(value);
}

/**
 * Read a `SERVICE_ROLES` value: `all`, or a comma-separated list of roles.
 *
 * Unset or blank is `all`. Spaces around an entry are ignored, a role named
 * twice counts once, and the result lists the roles in the order of
 * {@link SERVICE_ROLE_NAMES}.
 *
 * @returns the roles, or the problem with the value
 */
export function parseServiceRoles(
  value: string | undefined
): { readonly roles: readonly ServiceRole[] } | { readonly problem: string } {
  if (value === undefined || value.trim() === '') return { roles: SERVICE_ROLE_NAMES };
  const entries = value.split(',').map((entry) => entry.trim());
  if (entries.some((entry) => entry === '')) {
    return { problem: 'SERVICE_ROLES has an empty entry; list roles separated by single commas' };
  }
  if (entries.includes(ALL_SERVICE_ROLES)) {
    return entries.length === 1
      ? { roles: SERVICE_ROLE_NAMES }
      : {
          problem: `SERVICE_ROLES names "all" beside other roles; "all" already holds every role, so write it alone`,
        };
  }
  const unknown = entries.filter((entry) => !isServiceRole(entry));
  if (unknown.length > 0) {
    return {
      problem: `SERVICE_ROLES names an unknown role: ${unknown.map((entry) => `"${entry}"`).join(', ')}; the roles are ${SERVICE_ROLE_NAMES.join(', ')}, or all`,
    };
  }
  return { roles: SERVICE_ROLE_NAMES.filter((role) => entries.includes(role)) };
}

/** Blank is unset, as `${VAR:-}` in a Compose file expands to. */
function optionalSetting<T extends z.ZodType>(schema: T) {
  return z.preprocess(
    (value) => (typeof value === 'string' && value.trim() === '' ? undefined : value),
    schema.optional()
  );
}

/**
 * Service role environment configuration schema.
 */
export const serviceRolesEnvSchema = z.object({
  /**
   * The roles this process holds: `all` (the default), or a comma-separated
   * list of `web`, `api`, `admin`, `signer` and `delivery`.
   */
  SERVICE_ROLES: z
    .string()
    .optional()
    .transform((value, ctx) => {
      const parsed = parseServiceRoles(value);
      if ('problem' in parsed) {
        ctx.addIssue({ code: 'custom', message: parsed.problem });
        return z.NEVER;
      }
      return parsed.roles;
    }),
  /**
   * The signer service's URL, for a process that does not hold the `signer`
   * role. It is reached over mutual TLS, so it must be `https`.
   */
  SIGNER_URL: optionalSetting(
    z
      .url('SIGNER_URL must be a URL')
      .refine((value) => !URL.canParse(value) || new URL(value).protocol === 'https:', {
        message: 'SIGNER_URL must be an https URL: the signer service is reached over mutual TLS',
      })
  ),
  /** This process's certificate for internal traffic, as a PEM file. */
  INTERNAL_TLS_CERT_PATH: optionalSetting(z.string()),
  /** The private key of `INTERNAL_TLS_CERT_PATH`, as a PEM file. */
  INTERNAL_TLS_KEY_PATH: optionalSetting(z.string()),
  /** The CA certificates that issue internal peers' certificates, as a PEM file. */
  INTERNAL_TLS_CA_PATH: optionalSetting(z.string()),
});

export type ServiceRolesEnv = z.infer<typeof serviceRolesEnvSchema>;
