import { MisdirectedRequestError } from '@qauth-labs/shared-errors';
import { InvalidRealmHostError, normaliseRealmHost } from '@qauth-labs/shared-validation';
import type { FastifyInstance, FastifyPluginOptions, FastifyRequest, RouteOptions } from 'fastify';
import fp from 'fastify-plugin';

import {
  createRealmHostCache,
  type RealmHostCache,
  type RealmHostLookup,
  type RealmHostMatch,
} from '../helpers/realm-host-cache';
import { type RouteSurface, routeSurfaceProblem } from '../helpers/route-surface';

/** The `realm_hosts` row a request was resolved through. */
export interface ResolvedRealmHost {
  /** The host in its stored form: lower case, ASCII, no port. */
  readonly host: string;
  /** `primary` (the realm's issuer host) or `endpoint`. */
  readonly kind: RealmHostMatch['host']['kind'];
}

declare module 'fastify' {
  interface FastifyInstance {
    /**
     * The resolver's host cache. `clear()` makes the next request for every
     * host read `realm_hosts` again; the E2E harness calls it after it empties
     * the database.
     */
    realmHostCache: RealmHostCache;
  }

  interface FastifyRequest {
    /**
     * The realm whose host the request named (#486), as its row was read at
     * most the cache time ago. `null` only on a `none` route, such as
     * `/health`, and on a request that matched no route.
     */
    realm: RealmHostMatch['realm'] | null;
    /** The host the realm was found by, and its kind. `null` where {@link realm} is. */
    realmHost: ResolvedRealmHost | null;
  }
}

/** Options for {@link realmResolverPlugin}. */
export interface RealmResolverPluginOptions extends FastifyPluginOptions {
  /**
   * Finds the realm a normalised host belongs to. Defaults to
   * `fastify.repositories.realms.findByHost`; only a boot with no database
   * passes another.
   */
  lookup?: RealmHostLookup;
  /** How long a host that names a realm is cached, in milliseconds (30 s by default). */
  cacheTtlMs?: number;
  /** The cache's clock, in milliseconds. Defaults to `Date.now`. */
  now?: () => number;
}

export const REALM_RESOLVER_PLUGIN_NAME = '@qauth-labs/realm-resolver';

/** Why a request was refused, for the log line. Never sent. */
type RefusalReason =
  | 'malformed_host'
  | 'unknown_host'
  | 'realm_disabled'
  | 'realm_without_issuer'
  | 'endpoint_host';

/**
 * The preflight route `@fastify/cors` adds, `OPTIONS *`. It takes no route
 * config, so the resolver gives it the `api` surface: a preflight carries no
 * cookie, and the request it announces is checked against its own route.
 */
function isCorsPreflightRoute(route: RouteOptions): boolean {
  return route.method === 'OPTIONS' && route.url === '*';
}

/** Most characters of a refused host the log line keeps. */
const LOGGED_HOST_MAX_LENGTH = 300;

/**
 * Resolve the realm from the request host (ADR-019 Decision 1, issue #486).
 *
 * A request belongs to the realm whose primary host or endpoint host equals the
 * request's authority. The authority is `request.host`: the `Host` header, or
 * `X-Forwarded-Host` when the TCP peer is a `TRUST_PROXY` hop. It is normalised
 * with `normaliseRealmHost()`, the same function that wrote every stored host,
 * so the match is exact and case-insensitive on the port-less ASCII form, and
 * looked up in `realm_hosts` through a small in-process cache
 * (`helpers/realm-host-cache.ts`).
 *
 * The request is refused with `421 Misdirected Request` when the host names no
 * realm, names a disabled realm or a realm with no issuer, or is an endpoint
 * host and the route is a `browser` route. The refusal is thrown from the
 * `onRequest` hook, before any route code, cookie or body parser runs, so it
 * carries no realm context. There is no fallback to the default realm, in
 * simple mode either: there the default realm's primary host (from
 * `JWT_ISSUER`) and its `DEFAULT_REALM_ENDPOINT_HOSTS` are the only hosts in
 * `realm_hosts`. Otherwise the request carries `request.realm` and
 * `request.realmHost`.
 *
 * Each route says where it answers in `config.surface` (`helpers/route-surface.ts`).
 * An `onRoute` hook refuses to boot when a route has none. `onRoute` is not
 * retroactive, so this plugin MUST be registered before the routes, and it is
 * registered before the rate limiter too, so a per-realm limit can read the
 * realm.
 *
 * Not routed by host: a `none` route (`/health`), and a request that matches no
 * route, which gets the same 404 on every host. Routes registered outside the
 * app's scope, on the root instance in `main.ts` (Swagger UI at `/docs`, when
 * `ENABLE_SWAGGER` is on), do not pass through this plugin.
 */
export const realmResolverPlugin = fp<RealmResolverPluginOptions>(
  async (fastify: FastifyInstance, options: RealmResolverPluginOptions) => {
    let lookup = options.lookup;
    if (lookup === undefined) {
      if (!fastify.hasDecorator('repositories')) {
        throw new Error(
          'The realm resolver needs `fastify.repositories`: register the database plugin first'
        );
      }
      lookup = (host) => fastify.repositories.realms.findByHost(host);
    }
    const cache = createRealmHostCache({
      lookup,
      ...(options.cacheTtlMs === undefined ? {} : { ttlMs: options.cacheTtlMs }),
      ...(options.now === undefined ? {} : { now: options.now }),
    });

    fastify.decorate('realmHostCache', cache);
    fastify.decorateRequest('realm', null);
    fastify.decorateRequest('realmHost', null);

    fastify.addHook('onRoute', (route) => {
      if (route.config?.surface === undefined && isCorsPreflightRoute(route)) {
        route.config = { ...route.config, surface: 'api' };
      }
      const problem = routeSurfaceProblem(route);
      if (problem !== undefined) throw new Error(problem);
    });

    fastify.addHook('onRequest', async (request: FastifyRequest) => {
      if (request.is404) return;
      // A route that escaped the `onRoute` check above gets the strictest
      // realm-bound surface rather than none.
      const surface: RouteSurface = request.routeOptions.config.surface ?? 'browser';
      if (surface === 'none') return;

      const refuse = (reason: RefusalReason): never => {
        throw new MisdirectedRequestError({
          reason,
          host: request.host.slice(0, LOGGED_HOST_MAX_LENGTH),
        });
      };

      let host: string;
      try {
        host = normaliseRealmHost(request.host);
      } catch (error) {
        if (!(error instanceof InvalidRealmHostError)) throw error;
        return refuse('malformed_host');
      }

      const match = await cache.resolve(host);
      if (match === undefined) return refuse('unknown_host');
      if (!match.realm.enabled) return refuse('realm_disabled');
      if (match.realm.issuer === null) return refuse('realm_without_issuer');
      if (surface === 'browser' && match.host.kind !== 'primary') return refuse('endpoint_host');

      request.realm = match.realm;
      request.realmHost = { host: match.host.host, kind: match.host.kind };
    });
  },
  { name: REALM_RESOLVER_PLUGIN_NAME }
);

export default realmResolverPlugin;
