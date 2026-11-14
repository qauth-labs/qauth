import { isIP } from 'node:net';

import { REPOSITORY_NAMES, type RepositoryName } from '@qauth-labs/fastify-plugin-db';
import {
  DEFAULT_INTERNAL_HOST,
  DEFAULT_INTERNAL_PORT,
  describeServiceRoles,
  type InternalPeerRole,
  type InternalPeerRoles,
  isKeyMaterialVariable,
  isServiceRole,
  keyMaterialProblems,
  METRICS_PEER_ROLE,
  SERVICE_ROLE_NAMES,
  type ServiceRole,
  ServiceRoleBootError,
  type ServiceRoleProblem,
} from '@qauth-labs/server-config';

import {
  enabledInternalRouteModules,
  INTERNAL_ROUTE_MODULES,
  type InternalRouteModule,
  internalRouteModulesFor,
} from './internal/route-manifest';
import type { InternalTlsFiles } from './internal/tls-files';
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

export {
  describeServiceRoles,
  isKeyMaterialVariable,
  SERVICE_ROLE_NAMES,
  type ServiceRole,
  ServiceRoleBootError,
  type ServiceRoleProblem,
};

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
 * Why a route has no place on a process holding `processRoles`: it names no
 * role, names something that is not a role, or names only roles the process
 * does not hold, so a route an app-scope plugin tags `admin` is never served
 * on a `web` process. `undefined` when it names at least one role the process
 * holds.
 */
export function routeRolesProblem(
  route: RouteRolesSubject,
  processRoles: readonly ServiceRole[]
): string | undefined {
  const roles = route.config?.serviceRoles;
  const method = Array.isArray(route.method) ? route.method.join(',') : String(route.method);
  if (
    Array.isArray(roles) &&
    roles.length > 0 &&
    roles.every((role) => typeof role === 'string' && isServiceRole(role))
  ) {
    return roles.some((role) => processRoles.includes(role))
      ? undefined
      : `Route ${method} ${route.url} belongs to ${roles.join(',')}, a role this process does not hold (SERVICE_ROLES=${describeServiceRoles(processRoles)}); register it only where its roles run`;
  }
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
    // The session expiry and purge jobs (#550) run through the session service.
    plugins: ['sessions'],
    repositories: [],
  },
  api: {
    summary:
      'token, introspection, revocation, userinfo, registration, discovery, JWKS, the OID4VP endpoints, the account and developer APIs, SSF and the legacy /auth routes',
    // Its mail sender (registration, a resent verification link) reads a
    // realm transport's secret through the realm secret store (#529).
    plugins: [],
    repositories: ['realmSecrets'],
  },
  admin: {
    // The admin API's internal listener (#511): its token guard verifies with
    // the JWT plugin, finds the account in `users` and its grants in
    // `adminGrants`, and writes `adminAuditLog`. Its approval gate and
    // approval routes read and write `adminApprovals` (#512). The key
    // operations arrive on the same listener (#496).
    // The realm policy update and representation (#517) read and write the
    // realms' secrets through the realm secret store (#529): without it, the
    // policy store refuses a write of a secret, and cannot tell one set.
    summary: 'the admin API and key operations, on the internal listener',
    // The client operations (#632) hash a new client's secret.
    plugins: ['jwt', 'password'],
    // The plugin operations (#600) read and write `realmAuthMethodPlugins`.
    // An operator's verification of an account (#1052) reads its
    // credentials and records `user.verified` in `events`. The client
    // operations (#632) read and write `oauthClients`, and removing a
    // client's first-party profile revokes its `refreshTokens`.
    repositories: [
      'users',
      'oauthClients',
      'refreshTokens',
      'userCredentials',
      'events',
      'adminGrants',
      'adminAuditLog',
      'adminApprovals',
      'realmSecrets',
      'realmAuthMethodPlugins',
    ],
  },
  signer: {
    // The in-process signer and its key boot step are registered for this role
    // (`holdsSigner`), and so is the key rotation job (#542), which writes
    // its steps' audit events through the events repository. The boot
    // seeds the default realm's secrets from the environment where it can
    // encrypt them (#529), so this role builds the realm secret store.
    summary: 'the KEK, the private keys and the signer',
    plugins: [],
    repositories: ['realmSecrets'],
  },
  delivery: {
    // The reader, the SSF delivery route and the back-channel logout route
    // (#624), which reads its clients through `backchannelLogoutClients` and
    // POSTs through the egress client, whose allowlist an admin-set URI may
    // use; the event store's lag and age gauges in the metrics read `events`
    // and `eventRetention`, and the delivery history reads the role's own
    // queue through `eventDeliveries`.
    summary: 'the event delivery reader and event retention',
    plugins: ['eventDelivery', 'ssf', 'egress'],
    repositories: ['events', 'eventDeliveries', 'eventRetention', 'backchannelLogoutClients'],
  },
};

/**
 * The repositories every process reads: the realm resolver's and the default
 * realm boot step's, and the realms' published keys, public material with
 * which every process verifies a realm's tokens (#491).
 */
export const CORE_REPOSITORIES: readonly RepositoryName[] = ['realms', 'realmPublicKeys'];

/**
 * The plugins another plugin needs: the JWT plugin reads `fastify.dpop`, the
 * failure ladder's hard action tells the owner through the mail service
 * (`fastify.emailService`, #637), and the breach list's range lookup goes
 * through the egress client (`fastify.egress`, #635).
 */
const PLUGIN_DEPENDENCIES: Readonly<Partial<Record<RolePlugin, readonly RolePlugin[]>>> = {
  jwt: ['dpop'],
  failureLadder: ['email'],
  breachedPasswords: ['egress'],
};

/** The repositories a plugin reads through `fastify.repositories`. */
export const PLUGIN_REPOSITORIES: Readonly<Partial<Record<RolePlugin, readonly RepositoryName[]>>> =
  {
    // The session epochs (#642) come with the session service.
    sessions: ['realms', 'sessions', 'userSessionEpochs'],
    ssf: ['ssfStreams'],
  };

/** Whether a process with `roles` holds the signer, and so the keys. */
export function holdsSigner(roles: readonly ServiceRole[]): boolean {
  return roles.includes('signer');
}

/**
 * Whether a process with `roles` runs the default realm's boot step (#484),
 * which creates the realm on a fresh database and writes its hosts and
 * policies: any process that holds a role besides `delivery`. The delivery
 * role's database user gets its outbox and nothing beyond it (ADR-019
 * Decision 8, #498), so it may not write `realms`; it needs no realm to
 * start, and delivers the events of the realms the other roles created.
 */
export function bootsDefaultRealm(roles: readonly ServiceRole[]): boolean {
  return roles.some((role) => role !== 'delivery');
}

/**
 * Whether `roles` is every role: a single process, which is one trust domain
 * (ADR-019 Decision 9). Any other list splits the roles across processes.
 */
export function isSingleProcess(roles: readonly ServiceRole[]): boolean {
  return SERVICE_ROLE_NAMES.every((role) => roles.includes(role));
}

/**
 * Whether a process with `roles` runs the internal listener (#496): one that
 * holds `signer` while the roles are split, so that the processes without the
 * signer reach the signer service there (#497), and one whose roles have a
 * route module on the internal listener's manifest that the settings switch
 * on (`internal/route-manifest.ts`). A single process is one trust domain and
 * calls its own roles in-process: it runs the listener only for a module
 * marked `inSingleProcess`, the metrics a scraper reads while METRICS_ENABLED
 * is on (#500), and never serves the signer there.
 *
 * @param modules - the internal listener's route modules that are on:
 *   `enabledInternalRouteModules(settings)` unless a test names its own
 */
export function servesInternalListener(
  roles: readonly ServiceRole[],
  modules: readonly InternalRouteModule[] = INTERNAL_ROUTE_MODULES
): boolean {
  return (
    (holdsSigner(roles) && !isSingleProcess(roles)) ||
    internalRouteModulesFor(roles, modules).length > 0
  );
}

/**
 * Whether `host`, an INTERNAL_HOST value, names a loopback address only:
 * `localhost`, an address of `127.0.0.0/8`, or `::1`.
 */
export function isLoopbackHost(host: string): boolean {
  const bare = host.replace(/^\[|\]$/g, '');
  if (bare.toLowerCase() === 'localhost') return true;
  if (isIP(bare) === 4) return bare.startsWith('127.');
  // The URL parser writes an IPv6 address in its shortest form.
  return isIP(bare) === 6 && new URL(`http://[${bare}]/`).hostname === '[::1]';
}

/**
 * Whether a process with `roles` serves the Swagger UI and its spec routes
 * under `/docs` when ENABLE_SWAGGER is on: only one holding `api`, the role of
 * the API routes the document describes. The UI registers outside the app and
 * the route manifest, so this keeps it off `web`, `admin`, `signer` and
 * `delivery` processes.
 */
export function servesApiDocs(
  roles: readonly ServiceRole[],
  enableSwagger: boolean | undefined
): boolean {
  return enableSwagger === true && roles.includes('api');
}

/**
 * Whether a process with `roles` runs the admin API's internal listener
 * (#511): only one holding `admin`, and only while ADMIN_API_ENABLED is on.
 */
export function servesAdminListener(
  roles: readonly ServiceRole[],
  adminApiEnabled: boolean
): boolean {
  return adminApiEnabled && roles.includes('admin');
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

/** The settings the role checks read. */
export interface ServiceRoleSettings {
  readonly SERVICE_ROLES: readonly ServiceRole[];
  readonly SIGNER_URL?: string | undefined;
  readonly INTERNAL_TLS_CERT_PATH?: string | undefined;
  readonly INTERNAL_TLS_KEY_PATH?: string | undefined;
  readonly INTERNAL_TLS_CA_PATH?: string | undefined;
  /** The internal listener's address; `127.0.0.1` when unset. */
  readonly INTERNAL_HOST?: string | undefined;
  /** The internal listener's port; `3443` when unset. */
  readonly INTERNAL_PORT?: number | undefined;
  /** The roles of the internal listener's peers; none when unset. */
  readonly INTERNAL_PEER_ROLES?: InternalPeerRoles | undefined;
  /** The public listener's port, which the internal one must not take. */
  readonly PORT?: number | undefined;
  /**
   * Whether every process serves its metrics on the internal listener (#500);
   * on when unset, as the setting's own default is.
   */
  readonly METRICS_ENABLED?: boolean | undefined;
  /** Whether the admin API's listener runs, on ADMIN_API_PORT (#511). */
  readonly ADMIN_API_ENABLED?: boolean | undefined;
  readonly ADMIN_API_PORT?: number | undefined;
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

/** How a process runs its internal listener, from {@link internalListenerPlan}. */
export type InternalListenerPlan =
  | { readonly serves: false }
  | {
      readonly serves: true;
      /** Why it cannot start as configured; empty when it can. */
      readonly problems: readonly ServiceRoleProblem[];
      readonly host: string;
      readonly port: number;
      /**
       * The TLS files of mutual TLS; unset when `problems` names them, or on
       * a single process that serves plain HTTP on a loopback address.
       */
      readonly tls?: InternalTlsFiles;
      readonly peerRoles: InternalPeerRoles;
      /**
       * Without `tls`: the role a request from a loopback address calls as,
       * `metrics` (#500). Unset with `tls`.
       */
      readonly plainHttpPeerRole?: InternalPeerRole;
    };

/**
 * Whether a process runs the internal listener ({@link servesInternalListener}),
 * on which address, how, and why it cannot (#496, #500).
 *
 * - With the three internal TLS files, it serves mutual TLS, and needs
 *   INTERNAL_PEER_ROLES: without a known peer it would refuse every request.
 * - With some of them only, it cannot start: the missing ones are named.
 * - With none, a process whose roles are split cannot start either: the
 *   files are named, so the signer and the metrics are never served there
 *   without mutual TLS. A single process serves plain HTTP instead, on a
 *   loopback address only (INTERNAL_HOST), where a request from a loopback
 *   address reads the metrics as the `metrics` peer role and nothing else.
 * - INTERNAL_PORT must differ from PORT, and from ADMIN_API_PORT where the
 *   admin API's listener runs.
 *
 * @param modules - the internal listener's route modules that are on: the
 *   manifest's that `settings` switch on, unless a test names its own
 */
export function internalListenerPlan(
  settings: ServiceRoleSettings,
  modules: readonly InternalRouteModule[] = enabledInternalRouteModules(settings)
): InternalListenerPlan {
  const roles = settings.SERVICE_ROLES;
  if (!servesInternalListener(roles, modules)) return { serves: false };
  const named = `SERVICE_ROLES=${describeServiceRoles(roles)}`;
  const host = settings.INTERNAL_HOST ?? DEFAULT_INTERNAL_HOST;
  const port = settings.INTERNAL_PORT ?? DEFAULT_INTERNAL_PORT;
  const peerRoles = settings.INTERNAL_PEER_ROLES ?? new Map<string, InternalPeerRole>();
  const single = isSingleProcess(roles);
  const problems: ServiceRoleProblem[] = [];
  // A split process with the signer serves it there; any other serves only its metrics.
  const servesSigner = holdsSigner(roles) && !single;
  const serving = servesSigner
    ? `${named} serves the signer to the other roles on the internal listener`
    : `${named} serves its metrics on the internal listener`;
  const peerRolesExample = single
    ? '{"spiffe://example.org/prometheus":"metrics"}'
    : '{"spiffe://example.org/qauth/web":"web","spiffe://example.org/prometheus":"metrics"}';
  const peerRolesProblem = (): ServiceRoleProblem => ({
    variable: 'INTERNAL_PEER_ROLES',
    message: `INTERNAL_PEER_ROLES is required: ${serving} over mutual TLS, and refuses every peer whose certificate it does not map to a role; map each peer's SAN to its role, and a metrics scraper's to metrics, such as ${peerRolesExample}${servesSigner ? '' : ', or set METRICS_ENABLED=false where no scraper reads this process'}`,
  });

  const missing = INTERNAL_TLS_SETTINGS.filter((variable) => settings[variable] === undefined);
  let plainHttpPeerRole: InternalPeerRole | undefined;
  if (missing.length === 0) {
    if (peerRoles.size === 0) problems.push(peerRolesProblem());
  } else if (missing.length < INTERNAL_TLS_SETTINGS.length) {
    for (const variable of missing) {
      problems.push({
        variable,
        message: `${variable} is required: ${serving} over mutual TLS, which needs all three internal TLS files, and the others are set`,
      });
    }
    if (peerRoles.size === 0) problems.push(peerRolesProblem());
  } else if (single) {
    // One trust domain, and the listener serves the metrics alone: plain
    // HTTP, to a scraper on the same host or in the same network namespace.
    if (isLoopbackHost(host)) {
      plainHttpPeerRole = METRICS_PEER_ROLE;
    } else {
      problems.push({
        variable: 'INTERNAL_HOST',
        message: `INTERNAL_HOST must be a loopback address, such as 127.0.0.1, without the internal TLS files: ${serving} in plain HTTP on loopback only. To serve them on ${host}, set INTERNAL_TLS_CERT_PATH, INTERNAL_TLS_KEY_PATH and INTERNAL_TLS_CA_PATH, and map the scraper's certificate to metrics in INTERNAL_PEER_ROLES`,
      });
    }
  } else {
    for (const variable of missing) {
      problems.push({
        variable,
        message: `${variable} is required: ${serving}, over mutual TLS only while the roles are split, so no internal route is registered without it`,
      });
    }
    if (peerRoles.size === 0) problems.push(peerRolesProblem());
  }

  if (settings.PORT !== undefined && port === settings.PORT) {
    problems.push({
      variable: 'INTERNAL_PORT',
      message: `INTERNAL_PORT must differ from PORT (${settings.PORT}): the internal listener runs on its own port, never on the public one`,
    });
  }
  if (
    servesAdminListener(roles, settings.ADMIN_API_ENABLED === true) &&
    port === settings.ADMIN_API_PORT
  ) {
    problems.push({
      variable: 'INTERNAL_PORT',
      message: `INTERNAL_PORT must differ from ADMIN_API_PORT (${port}): the admin API keeps a listener of its own`,
    });
  }

  return {
    serves: true,
    problems,
    host,
    port,
    peerRoles,
    ...(plainHttpPeerRole === undefined ? {} : { plainHttpPeerRole }),
    ...(missing.length === 0
      ? {
          tls: {
            certPath: settings.INTERNAL_TLS_CERT_PATH as string,
            keyPath: settings.INTERNAL_TLS_KEY_PATH as string,
            caPath: settings.INTERNAL_TLS_CA_PATH as string,
          },
        }
      : {}),
  };
}

/**
 * Check a process's roles against its environment.
 *
 * A process without the `signer` role:
 *
 * - holds no key material: each variable {@link isKeyMaterialVariable} names
 *   is a problem that names it;
 * - reaches the signer service: `SIGNER_URL` and the internal TLS files are
 *   required.
 *
 * It needs no public key variable: it verifies a realm's tokens with the keys
 * the realm publishes in its key store (`realm_public_keys`, #491), which its
 * signer reads without a KEK.
 *
 * A process with the signer signs in-process, and a `SIGNER_URL` it is given
 * is reported as ignored. Where its roles are split, it serves the signer to
 * the other processes on the internal listener, over mutual TLS only
 * ({@link internalListenerPlan}): without the internal TLS files and
 * INTERNAL_PEER_ROLES, it refuses to boot.
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

  // The internal listener's transport and ports (#496), whatever else the
  // roles need.
  const internal = internalListenerPlan(settings);
  if (internal.serves) problems.push(...internal.problems);

  if (holdsSigner(roles)) {
    if (settings.SIGNER_URL !== undefined) {
      warnings.push({
        variable: 'SIGNER_URL',
        message: `SIGNER_URL is ignored: ${named} holds the signer role, so this process signs in-process`,
      });
    }
    return { problems, warnings };
  }

  // Refused before the configuration reads a key file too (`config/env.ts`);
  // checked again here for a caller that builds its settings another way.
  problems.push(...keyMaterialProblems(roles, raw));

  if (settings.SIGNER_URL === undefined) {
    problems.push({
      variable: 'SIGNER_URL',
      message: `SIGNER_URL is required: ${named} does not hold the signer role, so it reaches the signer service at SIGNER_URL over mutual TLS`,
    });
  }
  // A file the internal listener's plan already named is not named twice.
  const planned = new Set(problems.map((problem) => problem.variable));
  for (const variable of INTERNAL_TLS_SETTINGS) {
    if (settings[variable] === undefined && !planned.has(variable)) {
      problems.push({
        variable,
        message: `${variable} is required: ${named} reaches the signer service over mutual TLS`,
      });
    }
  }

  warnings.push({
    variable: 'SERVICE_ROLES',
    message: `${named} signs through the signer service, which this release cannot call yet: until it can, a request that needs a signature, an encryption or a cookie secret answers 503 on this process, and an event delivery waits; tokens still verify, with the realm's published keys`,
  });

  return { problems, warnings };
}
