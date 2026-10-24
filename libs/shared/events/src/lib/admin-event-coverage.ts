import { getEventType } from './registry';

/**
 * A test utility for the admin API (issue #459): every admin route that
 * changes something must emit an admin event in the transaction of its
 * change, and the route's own test must have seen it do so.
 *
 * ```ts
 * const coverage = adminEventCoverage();
 *
 * it('changes the policy', async () => {
 *   // ... call PATCH /admin/v1-rc.0/realms/:realmId/policies, read back the events ...
 *   coverage.record({ method: 'PATCH', url: '/admin/v1-rc.0/realms/:realmId/policies' }, events);
 * });
 *
 * afterAll(() => {
 *   expect(coverage.missing(adminRouteTable)).toEqual([]);
 * });
 * ```
 *
 * The route table is what the admin listener registered, as Fastify's
 * `onRoute` hook reports it. A route counts as covered only when a test
 * recorded an event of an `admin` type for it.
 */

/** One route of a route table: its methods and its URL pattern. */
export interface AdminRoute {
  readonly method: string | readonly string[];
  readonly url: string;
}

/** Methods that only read, and so emit no admin event. */
const READ_METHODS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'OPTIONS']);

const routeKey = (method: string, url: string) => `${method.toUpperCase()} ${url}`;

/** Admin event coverage of a route table, as {@link adminEventCoverage} collects it. */
export interface AdminEventCoverage {
  /**
   * Record what a route's test saw the route emit. Only an event of a
   * registered `admin` type covers the route.
   *
   * @param route - The route, by one method and its URL pattern.
   * @param emitted - The events the call emitted, as envelopes or as emitted.
   */
  record(
    route: { readonly method: string; readonly url: string },
    emitted: readonly { readonly type: string }[]
  ): void;
  /**
   * The routes of a table that change something (any method but GET, HEAD
   * and OPTIONS) and whose tests recorded no admin event, as `METHOD url`.
   */
  missing(table: readonly AdminRoute[]): string[];
}

/** Start collecting admin event coverage; see the module comment. */
export function adminEventCoverage(): AdminEventCoverage {
  const covered = new Set<string>();
  return {
    record(route, emitted) {
      if (emitted.some((event) => getEventType(event.type)?.category === 'admin')) {
        covered.add(routeKey(route.method, route.url));
      }
    },
    missing(table) {
      const missing = new Set<string>();
      for (const route of table) {
        const methods = typeof route.method === 'string' ? [route.method] : route.method;
        for (const method of methods) {
          const key = routeKey(method, route.url);
          if (!READ_METHODS.has(method.toUpperCase()) && !covered.has(key)) missing.add(key);
        }
      }
      return [...missing].sort();
    },
  };
}
