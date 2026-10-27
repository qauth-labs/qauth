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

/** `SERVICE_ROLES` as the operator would write it: `all`, or the list. */
export function describeServiceRoles(roles: readonly ServiceRole[]): string {
  return SERVICE_ROLE_NAMES.every((role) => roles.includes(role)) ? 'all' : roles.join(',');
}

/**
 * The roles whose routes read or set the browser session cookie: `web`, which
 * serves the sign-in and consent pages, and `api`, whose `/auth/logout` ends
 * the session. Only a process holding one of them needs
 * `SESSION_COOKIE_SECRET`, so only there does `NODE_ENV=production` refuse the
 * development default. The auth server's route manifest test holds this list
 * to the routes and plugins of each role.
 */
export const SESSION_COOKIE_ROLES: readonly ServiceRole[] = ['web', 'api'];

/** Whether a process with `roles` reads the session cookie ({@link SESSION_COOKIE_ROLES}). */
export function readsSessionCookie(roles: readonly ServiceRole[]): boolean {
  return roles.some((role) => SESSION_COOKIE_ROLES.includes(role));
}

/**
 * Whether the variable `name`, set to `value`, puts key material in a process:
 * the KEK and its adapters' settings (`KEK`, `KEK_PATH`, `KEK_PREVIOUS*`,
 * `KEK_<ADAPTER>_*`, and `KEK_PROVIDER` naming an adapter rather than the
 * default `local`), a JWT private key (`JWT_*_PRIVATE_KEY*`) or the OID4VP
 * verifier's signing key (`OID4VP_VERIFIER_SIGNING_KEY*`). A blank value is
 * unset.
 */
export function isKeyMaterialVariable(name: string, value: string | undefined): boolean {
  if (value === undefined || value.trim() === '') return false;
  if (name === 'KEK_PROVIDER') return value.trim() !== 'local';
  return (
    /^KEK(?:_|$)/.test(name) ||
    /^JWT_(?:[A-Z0-9]+_)*PRIVATE_KEY/.test(name) ||
    /^OID4VP_VERIFIER_SIGNING_KEY/.test(name)
  );
}

/** One reason a process cannot start with its roles. */
export interface ServiceRoleProblem {
  /** The variable to set or remove. */
  readonly variable: string;
  readonly message: string;
}

/**
 * The key variables a process with `roles` must not have, each with its
 * refusal: none where the process holds the signer, which alone holds keys
 * (ADR-019 Decision 9).
 *
 * The auth server checks this before its configuration reads any key file,
 * so a process without the signer never loads the key it refuses.
 *
 * @param raw - the environment, after `.env` and the key aliases
 */
export function keyMaterialProblems(
  roles: readonly ServiceRole[],
  raw: Readonly<Record<string, string | undefined>>
): ServiceRoleProblem[] {
  if (roles.includes('signer')) return [];
  const named = `SERVICE_ROLES=${describeServiceRoles(roles)}`;
  return Object.keys(raw)
    .sort()
    .filter((variable) => isKeyMaterialVariable(variable, raw[variable]))
    .map((variable) => ({
      variable,
      message: `${variable} is set, but ${named} does not hold the signer role, and only the signer holds keys. Remove ${variable} from this process: give it to the processes whose SERVICE_ROLES name signer, or all`,
    }));
}

/** A boot refused for its service roles, naming every variable at fault. */
export class ServiceRoleBootError extends Error {
  readonly problems: readonly ServiceRoleProblem[];

  constructor(problems: readonly ServiceRoleProblem[]) {
    super(
      `The service roles cannot start:\n${problems.map((problem) => `- ${problem.message}`).join('\n')}`
    );
    this.name = 'ServiceRoleBootError';
    this.problems = problems;
  }
}
