import { REPOSITORY_NAMES, type RepositoryName } from '@qauth-labs/fastify-plugin-db';
import { isServiceRole, SERVICE_ROLE_NAMES, type ServiceRole } from '@qauth-labs/server-config';

import { SERVER_JOBS } from './jobs';
import { ROLE_PLUGINS, type RolePlugin, routeModulesFor } from './route-manifest';

/**
 * SERVICE ROLES (ADR-019 Decisions 8 and 9, issue #495).
 *
 * One codebase starts as one or more roles (`SERVICE_ROLES`). A process
 * registers only the routes of its roles (`route-manifest.ts`), the plugins
 * those routes and roles use, the repositories they read and write, and the
 * jobs placed on its roles (`jobs/index.ts`). `all`, the default, holds every
 * role in one process: a single deployment, which is one trust domain and
 * runs as it did before roles existed.
 *
 * Only the `signer` role holds keys. A process without it refuses to boot when
 * it finds key material in its environment, and needs the signer service's
 * address and the internal TLS files: the separation protects keys once the
 * roles run on separate nodes.
 */

export { SERVICE_ROLE_NAMES, type ServiceRole };

declare module 'fastify' {
  interface FastifyContextConfig {
    /**
     * The service roles whose processes register the route (#495), set from
     * its module's entry in the route manifest when it registers. Every route
     * of the app has one; the app refuses to boot otherwise.
     */
    serviceRoles?: readonly ServiceRole[];
  }
}

/** The parts of a route's options {@link routeRolesProblem} reads. */
export interface RouteRolesSubject {
  readonly method: string | readonly string[];
  readonly url: string;
  readonly config?: { readonly serviceRoles?: unknown };
}

/**
 * Why a route has no place among the roles: it names none, or names something
 * that is not a role. `undefined` when it names at least one role.
 */
export function routeRolesProblem(route: RouteRolesSubject): string | undefined {
  const roles = route.config?.serviceRoles;
  if (
    Array.isArray(roles) &&
    roles.length > 0 &&
    roles.every((role) => typeof role === 'string' && isServiceRole(role))
  ) {
    return undefined;
  }
  const method = Array.isArray(route.method) ? route.method.join(',') : String(route.method);
  return roles === undefined
    ? `Route ${method} ${route.url} has no service role; register its module through the route manifest (route-manifest.ts) with the roles that serve it`
    : `Route ${method} ${route.url} names no known service role; use ${SERVICE_ROLE_NAMES.join(', ')}`;
}

/** What a role brings beyond the routes of the manifest. */
export interface ServiceRoleDefinition {
  /** What the role runs, for the boot log and the docs. */
  readonly summary: string;
  /** Plugins the role registers whatever its routes are. */
  readonly plugins: readonly RolePlugin[];
  /** Repositories the role reads beyond its routes' and its jobs'. */
  readonly repositories: readonly RepositoryName[];
}

/** Every role, with what it brings beyond its routes and jobs. */
export const SERVICE_ROLE_DEFINITIONS: Readonly<Record<ServiceRole, ServiceRoleDefinition>> = {
  web: {
    summary:
      'the browser-session endpoints: authorize, the ceremony pages, consents and wallet linking',
    // The session purge job goes here when it lands.
    plugins: [],
    repositories: [],
  },
  api: {
    summary:
      'token, introspection, revocation, userinfo, registration, discovery, JWKS, the OID4VP endpoints, the account and developer APIs, SSF and the legacy /auth routes',
    plugins: [],
    repositories: [],
  },
  admin: {
    // The admin API (#511) and the key operations arrive on the internal
    // listener (#496); until then the role serves /health and /metrics.
    summary: 'the admin API and key operations, on the internal listener',
    plugins: [],
    repositories: [],
  },
  signer: {
    // The in-process signer and its key boot step are registered for this role
    // (`holdsSigner`); the key jobs (#542) go here when they land.
    summary: 'the KEK, the private keys and the signer',
    plugins: [],
    repositories: [],
  },
  delivery: {
    // The reader and the SSF delivery route; the event store's lag and age
    // gauges on /metrics read `events` and `eventRetention`.
    summary: 'the event delivery reader and event retention',
    plugins: ['eventDelivery', 'ssf'],
    repositories: ['events', 'eventRetention'],
  },
};

/** The repositories every process reads: the realm resolver's and the default realm boot step's. */
export const CORE_REPOSITORIES: readonly RepositoryName[] = ['realms'];

/** The plugins another plugin needs: the JWT plugin reads `fastify.dpop`. */
const PLUGIN_DEPENDENCIES: Readonly<Partial<Record<RolePlugin, readonly RolePlugin[]>>> = {
  jwt: ['dpop'],
};

/** The repositories a plugin reads through `fastify.repositories`. */
export const PLUGIN_REPOSITORIES: Readonly<Partial<Record<RolePlugin, readonly RepositoryName[]>>> =
  {
    sessions: ['realms', 'sessions'],
    ssf: ['ssfStreams'],
  };

/** Whether a process with `roles` holds the signer, and so the keys. */
export function holdsSigner(roles: readonly ServiceRole[]): boolean {
  return roles.includes('signer');
}

/**
 * The plugins a process with `roles` registers beyond those every process
 * registers: what its routes call, what its roles bring, and what those need.
 */
export function pluginsFor(roles: readonly ServiceRole[]): ReadonlySet<RolePlugin> {
  const plugins = new Set<RolePlugin>();
  const add = (plugin: RolePlugin): void => {
    if (plugins.has(plugin)) return;
    plugins.add(plugin);
    for (const dependency of PLUGIN_DEPENDENCIES[plugin] ?? []) add(dependency);
  };
  for (const entry of routeModulesFor(roles)) entry.plugins.forEach(add);
  for (const role of roles) SERVICE_ROLE_DEFINITIONS[role].plugins.forEach(add);
  // In the order the app registers them, for a stable boot log.
  return new Set(ROLE_PLUGINS.filter((plugin) => plugins.has(plugin)));
}

/**
 * The repositories a process with `roles` builds: the boot-time list the
 * database plugin takes. Any other repository is never built, and a read of
 * it throws.
 */
export function repositoriesFor(roles: readonly ServiceRole[]): readonly RepositoryName[] {
  const used = new Set<RepositoryName>(CORE_REPOSITORIES);
  for (const entry of routeModulesFor(roles)) entry.repositories.forEach((name) => used.add(name));
  for (const plugin of pluginsFor(roles)) {
    (PLUGIN_REPOSITORIES[plugin] ?? []).forEach((name) => used.add(name));
  }
  for (const job of SERVER_JOBS) {
    if (roles.includes(job.role)) job.repositories.forEach((name) => used.add(name));
  }
  for (const role of roles) {
    SERVICE_ROLE_DEFINITIONS[role].repositories.forEach((name) => used.add(name));
  }
  return REPOSITORY_NAMES.filter((name) => used.has(name));
}

/** `SERVICE_ROLES` as the operator would write it: `all`, or the list. */
export function describeServiceRoles(roles: readonly ServiceRole[]): string {
  return SERVICE_ROLE_NAMES.every((role) => roles.includes(role)) ? 'all' : roles.join(',');
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

/** The settings the role checks read. */
export interface ServiceRoleSettings {
  readonly SERVICE_ROLES: readonly ServiceRole[];
  readonly SIGNER_URL?: string | undefined;
  readonly INTERNAL_TLS_CERT_PATH?: string | undefined;
  readonly INTERNAL_TLS_KEY_PATH?: string | undefined;
  readonly INTERNAL_TLS_CA_PATH?: string | undefined;
  /** The parsed public key; only a process without the signer that verifies tokens needs it. */
  readonly JWT_PUBLIC_KEY?: string | undefined;
}

/** One reason a process cannot start with its roles. */
export interface ServiceRoleProblem {
  /** The variable to set or remove. */
  readonly variable: string;
  readonly message: string;
}

/** What the role checks found: refusals, and lines for the boot log. */
export interface ServiceRoleCheck {
  readonly problems: readonly ServiceRoleProblem[];
  readonly warnings: readonly ServiceRoleProblem[];
}

/** The internal TLS files a process without the signer needs beside `SIGNER_URL`. */
const INTERNAL_TLS_SETTINGS = [
  'INTERNAL_TLS_CERT_PATH',
  'INTERNAL_TLS_KEY_PATH',
  'INTERNAL_TLS_CA_PATH',
] as const;

/**
 * Check a process's roles against its environment.
 *
 * A process without the `signer` role:
 *
 * - holds no key material: each variable {@link isKeyMaterialVariable} names
 *   is a problem that names it;
 * - reaches the signer service: `SIGNER_URL` and the internal TLS files are
 *   required;
 * - verifies tokens with the public key when it registers the JWT plugin, so
 *   `JWT_PUBLIC_KEY` (or `JWT_PUBLIC_KEY_PATH`) is required there.
 *
 * A process with the signer signs in-process, and a `SIGNER_URL` it is given
 * is reported as ignored.
 *
 * @param settings - the parsed configuration
 * @param raw - the environment it was parsed from, for the variable names
 */
export function checkServiceRoles(
  settings: ServiceRoleSettings,
  raw: Readonly<Record<string, string | undefined>>
): ServiceRoleCheck {
  const roles = settings.SERVICE_ROLES;
  const named = `SERVICE_ROLES=${describeServiceRoles(roles)}`;
  const problems: ServiceRoleProblem[] = [];
  const warnings: ServiceRoleProblem[] = [];

  if (holdsSigner(roles)) {
    if (settings.SIGNER_URL !== undefined) {
      warnings.push({
        variable: 'SIGNER_URL',
        message: `SIGNER_URL is ignored: ${named} holds the signer role, so this process signs in-process`,
      });
    }
    return { problems, warnings };
  }

  for (const variable of Object.keys(raw).sort()) {
    if (isKeyMaterialVariable(variable, raw[variable])) {
      problems.push({
        variable,
        message: `${variable} is set, but ${named} does not hold the signer role, and only the signer holds keys. Remove ${variable} from this process: give it to the processes whose SERVICE_ROLES name signer, or all`,
      });
    }
  }

  if (settings.SIGNER_URL === undefined) {
    problems.push({
      variable: 'SIGNER_URL',
      message: `SIGNER_URL is required: ${named} does not hold the signer role, so it reaches the signer service at SIGNER_URL over mutual TLS`,
    });
  }
  for (const variable of INTERNAL_TLS_SETTINGS) {
    if (settings[variable] === undefined) {
      problems.push({
        variable,
        message: `${variable} is required: ${named} reaches the signer service over mutual TLS`,
      });
    }
  }

  if (pluginsFor(roles).has('jwt') && settings.JWT_PUBLIC_KEY === undefined) {
    problems.push({
      variable: 'JWT_PUBLIC_KEY',
      message: `JWT_PUBLIC_KEY or JWT_PUBLIC_KEY_PATH is required: ${named} verifies access tokens and holds no private key to derive the public key from`,
    });
  }

  warnings.push({
    variable: 'SERVICE_ROLES',
    message: `${named} signs through the signer service, which this release cannot call yet: token issuance and every other signature answer 503 on this process until it can`,
  });

  return { problems, warnings };
}

/** A boot refused by {@link checkServiceRoles}, naming every variable at fault. */
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
