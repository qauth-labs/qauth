import cors from '@fastify/cors';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import { answerRouteNotFound } from '../helpers/request-bounds';
import type { RouteSurface } from '../helpers/route-surface';

declare module 'fastify' {
  interface FastifyContextConfig {
    /**
     * `@fastify/cors`'s route-level override. `false` leaves the route out of
     * CORS: its answers carry no `Access-Control-*` header. {@link corsPlugin}
     * sets it on every `browser` route; a route does not set it itself.
     */
    cors?: false;
  }
}

/** The surface whose routes are left out of CORS. */
const NO_CORS_SURFACE: RouteSurface = 'browser';

export const CORS_PLUGIN_NAME = '@qauth-labs/cors';

/** The options {@link corsPlugin} takes from the environment. */
export interface CorsPluginOptions {
  /** `CORS_ORIGIN`: one origin, or a comma-separated list of them. */
  readonly corsOrigin?: string | undefined;
  /** Whether `NODE_ENV` is `production`, where an unset `CORS_ORIGIN` allows no origin. */
  readonly production: boolean;
}

/**
 * The `origin` option `@fastify/cors` gets (F-06): the origins `CORS_ORIGIN`
 * lists; with none, no origin in production (fail-closed) and `*` elsewhere,
 * for local development.
 *
 * `CORS_ORIGIN` holds one origin or a comma-separated list, as the env
 * examples document. It is split and trimmed into an array so `@fastify/cors`
 * matches each origin: the raw comma string would be one literal origin that
 * never matches. Empty entries, such as from a trailing comma, are dropped.
 */
export function corsOriginOption(options: CorsPluginOptions): string[] | '*' | false {
  const origins = (options.corsOrigin ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean);
  if (origins.length > 0) return origins;
  return options.production ? false : '*';
}

/** A route of the app, as the preflight check matches it. */
interface KnownRoute {
  /** Whether it is left out of CORS: a `browser` route. */
  readonly noCors: boolean;
  /** Its methods, upper-case. */
  readonly methods: ReadonlySet<string>;
  /** Its URL pattern's path segments: `:name` is a parameter, `*` the rest. */
  readonly segments: readonly string[];
}

/** The non-empty segments of a path. */
function pathSegments(path: string): string[] {
  return path.split('/').filter((segment) => segment !== '');
}

/**
 * The path segments of a request-target, percent-decoded one by one, or
 * `undefined` when one is not valid percent-encoding.
 *
 * Decoding segment by segment keeps an encoded `/` (`%2F`) inside its
 * segment, as the router does. Dropping empty segments makes a trailing or
 * doubled slash match too, which the router (`ignoreTrailingSlash`) partly
 * does, so the check may cover a path no route serves. It reads an
 * origin-form request-target, the form a browser sends: the absolute form
 * (`OPTIONS http://host/path`), which the router also accepts, matches no
 * pattern.
 */
function requestSegments(url: string): string[] | undefined {
  const end = url.search(/[?#]/);
  const path = end === -1 ? url : url.slice(0, end);
  try {
    return pathSegments(path).map((segment) => decodeURIComponent(segment));
  } catch {
    return undefined;
  }
}

/**
 * Whether `segments` fall under `pattern`. A pattern segment that holds a
 * parameter matches any one segment, and a `*` matches the rest.
 */
function matchesPattern(pattern: readonly string[], segments: readonly string[]): boolean {
  for (const [index, part] of pattern.entries()) {
    if (part === '*') return true;
    const segment = segments[index];
    if (segment === undefined) return false;
    if (!part.includes(':') && part !== segment) return false;
  }
  return pattern.length === segments.length;
}

/**
 * The method a preflight announces (`Access-Control-Request-Method`), or
 * `undefined` when the request names none.
 */
function announcedMethod(request: FastifyRequest): string | undefined {
  const header = request.headers['access-control-request-method'];
  const method = typeof header === 'string' ? header.trim().toUpperCase() : '';
  return method === '' ? undefined : method;
}

/**
 * CORS for the app (F-06), with the browser routes left out (#930).
 *
 * `@fastify/cors` answers with the origins of {@link corsOriginOption}. A route
 * whose `config.surface` is `browser` (`helpers/route-surface.ts`) gets no
 * CORS at all, in every environment and whatever `CORS_ORIGIN` holds: no
 * `Access-Control-*` header on its answers, and no answer to a preflight for
 * it. OAuth 2.1 (draft-ietf-oauth-v2-1-17 §3.1) says CORS MUST NOT be
 * supported at the authorization endpoint, since the client does not call it:
 * it sends the user agent there. The other browser routes, the `/ui/*`
 * sign-in, consent and wallet pages, `/consents`, `/auth/link/wallet` and the
 * verification page `GET /auth/verify`, are reached the same way or called
 * from those pages, on the realm's own origin. No cross-origin caller needs
 * them: a page is navigated to, and a call the session cookie authorizes
 * could not be made cross-origin before either, since the CORS answers never
 * allowed credentials.
 *
 * Every other route keeps CORS. The token endpoint needs it: OAuth 2.1 §3.2
 * and §9.3.4 require an authorization server that supports browser-based
 * applications to send the CORS header fields there, so such an
 * application's origin goes in `CORS_ORIGIN`.
 *
 * Two hooks do it, both on the app's scope, so both MUST be in place before
 * the routes register:
 *
 * - An `onRoute` hook sets `config.cors = false`, `@fastify/cors`'s own
 *   route-level switch, on every `browser` route. It is keyed to the route,
 *   not to its URL, so every spelling of a path the router sends to the route
 *   is covered.
 * - A preflight names its target only by its URL and announced method: the
 *   router sends every `OPTIONS` request to `@fastify/cors`'s own `OPTIONS *`
 *   route, whose config is not the target's. An `onRequest` hook, added before
 *   `@fastify/cors` adds its own, answers an `OPTIONS` request for a `browser`
 *   route as a path no route serves (`answerRouteNotFound`), the 404 a
 *   preflight gets where CORS is off. It matches the request path against the
 *   patterns of the app's routes: a path a `browser` route serves gets no
 *   preflight answer, whatever method it announces, unless a route of another
 *   surface serves that path and method, as the JSON `POST /auth/verify` does
 *   beside the verification page. A preflight it fails to match is still
 *   harmless: the answer to the request itself carries no
 *   `Access-Control-Allow-Origin`, so the browser does not hand it to the
 *   calling page.
 */
export const corsPlugin = fp<CorsPluginOptions>(
  async (fastify: FastifyInstance, options: CorsPluginOptions) => {
    const knownRoutes: KnownRoute[] = [];

    fastify.addHook('onRoute', (route) => {
      // `@fastify/cors`'s own preflight route, which matches every path.
      if (route.method === 'OPTIONS' && route.url === '*') return;
      const noCors = route.config?.surface === NO_CORS_SURFACE;
      if (noCors) route.config = { ...route.config, cors: false };
      knownRoutes.push({
        noCors,
        methods: new Set([route.method].flat().map((method) => method.toUpperCase())),
        segments: pathSegments(route.url),
      });
    });

    const preflightsNoCorsRoute = (request: FastifyRequest): boolean => {
      const segments = requestSegments(request.url);
      if (segments === undefined) return false;
      const onPath = knownRoutes.filter((route) => matchesPattern(route.segments, segments));
      if (!onPath.some((route) => route.noCors)) return false;
      const method = announcedMethod(request);
      return (
        method === undefined || !onPath.some((route) => !route.noCors && route.methods.has(method))
      );
    };

    // Added before `@fastify/cors` registers its own `onRequest` hook, so it
    // runs first: hooks of one scope run in the order they were added.
    fastify.addHook('onRequest', async (request, reply) => {
      if (request.method !== 'OPTIONS' || !preflightsNoCorsRoute(request)) return undefined;
      // Returning the reply is how an async hook tells Fastify it has answered.
      return answerRouteNotFound(request, reply);
    });

    await fastify.register(cors, { origin: corsOriginOption(options) });
  },
  { name: CORS_PLUGIN_NAME }
);

export default corsPlugin;
