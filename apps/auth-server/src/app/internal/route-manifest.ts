import type { ServiceRole } from '@qauth-labs/server-config';
import type { FastifyPluginAsync, RouteOptions } from 'fastify';

/**
 * THE INTERNAL LISTENER'S ROUTES (ADR-019 Decision 8, issue #496).
 *
 * The internal listener registers its routes from this manifest, by role, as
 * the public listener registers its own from `../route-manifest.ts`: a module
 * registers on a process that holds one of its roles, and every route sits
 * under `/internal/`, a path the public listener refuses to register. So no
 * route answers on both listeners.
 *
 * The manifest is empty until the signer service (#497) adds its routes under
 * `/internal/signer/v1-rc.0`, for the `signer` role. Each module names the
 * peer roles that may call it (`peerRoles`): the listener refuses a peer with
 * no role, and a peer whose role the module does not name, with 403 before
 * the route runs. A route reads the caller's role with
 * `requestPeerRole(request)` (`./listener.ts`) to decide what that role may
 * do within the module.
 */

/** The path every internal route sits under. */
export const INTERNAL_PATH_PREFIX = '/internal';

/** One route module of the internal listener and where it runs. */
export interface InternalRouteModule {
  /** The module's name, for the boot log and the boot's refusals. */
  readonly module: string;
  /** The URL prefix its routes are registered under: `/internal/` and below. */
  readonly prefix: string;
  /** The roles whose processes register it. Never empty. */
  readonly roles: readonly ServiceRole[];
  /**
   * The roles of the peers that may call it, as INTERNAL_PEER_ROLES maps
   * their certificates: a peer of any other role gets 403 on every route of
   * the module. Never empty: the boot is refused otherwise.
   */
  readonly peerRoles: readonly ServiceRole[];
  /** The module, imported when a process registers it. */
  readonly load: () => Promise<{ readonly default: FastifyPluginAsync }>;
}

/** Every route module of the internal listener. */
export const INTERNAL_ROUTE_MODULES: readonly InternalRouteModule[] = Object.freeze([]);

/** The modules a process with `roles` registers on its internal listener. */
export function internalRouteModulesFor(
  roles: readonly ServiceRole[],
  modules: readonly InternalRouteModule[] = INTERNAL_ROUTE_MODULES
): readonly InternalRouteModule[] {
  return modules.filter((entry) => entry.roles.some((role) => roles.includes(role)));
}

/**
 * Why `entry` cannot register on the internal listener, or `undefined`: it
 * must name at least one peer role that may call it, so no module is open to
 * every peer by omission.
 */
export function internalModuleProblem(entry: InternalRouteModule): string | undefined {
  if (entry.peerRoles.length > 0) return undefined;
  return `The internal route module ${entry.module} names no peer role: list in peerRoles the roles whose peers may call it`;
}

/** A path under `/internal`, or `/internal` itself. */
const INTERNAL_PATH = /^\/internal(?:\/|$)/;

/** `GET /path`, or `GET,POST /path`. */
function describeRoute(route: Pick<RouteOptions, 'method' | 'url'>): string {
  const methods = Array.isArray(route.method) ? route.method.join(',') : route.method;
  return `${methods} ${route.url}`;
}

/**
 * Why `route` cannot be served on the internal listener, or `undefined`: its
 * path must sit under `/internal/`, which the public listener never serves.
 */
export function internalRouteProblem(
  route: Pick<RouteOptions, 'method' | 'url'>
): string | undefined {
  const below = `${INTERNAL_PATH_PREFIX}/`;
  if (route.url.startsWith(below) && route.url.length > below.length) return undefined;
  return `${describeRoute(route)}: every route of the internal listener sits under ${INTERNAL_PATH_PREFIX}/, a path the public listener never serves`;
}

/**
 * Why a route of the public listener cannot be served there, or
 * `undefined`: a path under `/internal` registers only on the internal
 * listener (`./listener.ts`), never on the public one.
 */
export function publicInternalRouteProblem(
  route: Pick<RouteOptions, 'method' | 'url'>
): string | undefined {
  if (!INTERNAL_PATH.test(route.url)) return undefined;
  return `${describeRoute(route)} is an internal route: it registers only on the internal listener (internal/listener.ts), never on the public one`;
}
