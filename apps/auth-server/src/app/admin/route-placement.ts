import type { RouteOptions } from 'fastify';

import { API_FAMILY_PREFIXES } from '../api-conventions/families';

/**
 * Where an admin route may be served (ADR-019 Decisions 1 and 7, #511): only
 * on the admin listener, and only under the realm it acts on.
 */

/** The path every admin route starts with: the realm it acts on (ADR-019 Decision 1). */
export const ADMIN_REALM_ROUTE_PREFIX = `${API_FAMILY_PREFIXES.admin}/realms/:realmId`;

/** `GET /path`, or `GET,POST /path`. */
function describeRoute(route: Pick<RouteOptions, 'method' | 'url'>): string {
  const methods = Array.isArray(route.method) ? route.method.join(',') : route.method;
  return `${methods} ${route.url}`;
}

/**
 * Why `route` cannot be served behind the admin pipeline, or `undefined`: its
 * path must name the realm it acts on, `/admin/v1-rc.0/realms/:realmId` or a
 * path below it. The listener takes the realm from the path and never from
 * the host, and the audit row goes to that realm's chain.
 */
export function adminRealmRouteProblem(
  route: Pick<RouteOptions, 'method' | 'url'>
): string | undefined {
  if (
    route.url === ADMIN_REALM_ROUTE_PREFIX ||
    route.url.startsWith(`${ADMIN_REALM_ROUTE_PREFIX}/`)
  ) {
    return undefined;
  }
  return `${describeRoute(route)}: every admin route acts on the realm its path names, under ${ADMIN_REALM_ROUTE_PREFIX}`;
}

/** A path under `/admin`, versioned or not: the admin API's, or one it may take later. */
const ADMIN_PATH = /^\/admin(?:\/|$)/;

/**
 * Why a route of the public listener's route modules cannot be served there,
 * or `undefined`: a path under `/admin`, whatever its version or none,
 * registers only on the admin listener (`admin/listener.ts`).
 */
export function publicRouteProblem(
  route: Pick<RouteOptions, 'method' | 'url'>
): string | undefined {
  if (!ADMIN_PATH.test(route.url)) return undefined;
  return `${describeRoute(route)} is an admin API route: it registers only on the admin listener (admin/listener.ts), never on the public one`;
}
