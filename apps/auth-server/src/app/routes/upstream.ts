import rateLimit from '@fastify/rate-limit';
import {
  type AuthMethodRouteHost,
  mountAuthMethodFamilyRoutes,
  mountAuthMethodRoutes,
  UPSTREAM_OIDC_TYPE_PATTERN,
} from '@qauth-labs/fastify-plugin-federation';
import type { FastifyPluginAsync, FastifyRequest } from 'fastify';

import { env } from '../../config/env';
import { authMethodPluginEnabledIn } from '../helpers/auth-method-plugins';
import { createInteractionEngines, type InteractionEngines } from '../helpers/interaction-engines';
import { realmRateLimitKey } from '../helpers/realm-rate-limit';
import { answerRouteNotFound } from '../helpers/request-bounds';
import { requestRealm } from '../helpers/request-realm';
import { upstreamOidcRoutes, upstreamProviderCatalog } from '../helpers/upstream-providers';
import { upstreamCallbackRateLimit, upstreamRouteHost } from '../helpers/upstream-sign-in';

/**
 * THE CALLBACKS OF THE REALM'S UPSTREAM PROVIDERS (ADR-019 Decision 12,
 * issues #599, #600 and #639), under `/upstream/<type>` on the realm host:
 *
 * - each generic OpenID Connect provider a realm configured
 *   (`realm_upstream_providers`, #601), by one route per declared route under
 *   `/upstream/:type`, whose handler runs the routes of the request realm's
 *   provider of that type: a type the realm has not, or has off, answers as
 *   a path no route serves;
 * - each loaded AuthMethod plugin's routes, at its own prefix, mounted by
 *   `mountAuthMethodRoutes` from the provider registry's method of each
 *   installed plugin's type, and no other method's.
 *
 * Both answer through one host (`helpers/upstream-sign-in.ts`): a callback
 * completes the sign-in its start left pending in this browser, and every
 * callback is rate-limited as a sign-in form post is.
 *
 * A route of a plugin the request's realm has not enabled answers as a path
 * no route serves: the `not_found` problem document, from a `preParsing`
 * hook, before the body is read, without the request ceiling's headers, so
 * neither its status, its body nor a validation error says whether the realm
 * has the plugin on. It runs after the request ceiling, so a flood of such
 * requests is limited before it reaches the database; a flood past the
 * ceiling answers 429 where an unknown path answers 404, which tells that a
 * plugin of that type is installed in the deployment, never which realms
 * have it on.
 */

/** The headers the request ceiling sets before a route answers. */
const RATE_LIMIT_HEADERS = ['x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset'];

/** The `<type>` segment of a mounted route's path, `/upstream/<type>/...`. */
function routeType(url: string | undefined): string | undefined {
  const match = /^\/upstream\/([^/]+)\//.exec(url ?? '');
  return match?.[1];
}

const upstreamRoutes: FastifyPluginAsync = async (fastify) => {
  const catalog = upstreamProviderCatalog(fastify);
  let engines: InteractionEngines | undefined;
  const host: AuthMethodRouteHost = upstreamRouteHost(fastify, {
    catalog,
    engines: () => (engines ??= createInteractionEngines(fastify)),
  });
  const config = upstreamCallbackRateLimit();

  // Every callback has the request ceiling of the app's `@fastify/rate-limit`,
  // which `app.ts` registers before the route manifest loads this plugin, and
  // its own `config.rateLimit`. CodeQL's `js/missing-rate-limiting` cannot
  // follow that registration into this plugin, so it is registered here too
  // when the app has none, as the admin pipeline does: never in the app, which
  // registers it first, and never when an operator turned rate limiting off.
  if (env.RATE_LIMIT_ENABLED && !fastify.hasDecorator('rateLimit')) {
    await fastify.register(rateLimit, {
      global: true,
      max: env.LOGIN_RATE_LIMIT,
      timeWindow: env.LOGIN_RATE_WINDOW * 1000,
      keyGenerator: realmRateLimitKey,
    });
  }

  // The realm's generic OpenID Connect providers (#639), resolved per
  // request: in a scope of their own, outside the plugins' gate below.
  await fastify.register(async (scope) => {
    mountAuthMethodFamilyRoutes(
      scope,
      {
        routes: upstreamOidcRoutes(),
        resolve: async (type, request) =>
          UPSTREAM_OIDC_TYPE_PATTERN.test(type)
            ? (await catalog.find(requestRealm(request).id, type))?.method
            : undefined,
        notFound: async (request, reply) => answerRouteNotFound(request, reply),
      },
      host,
      { config }
    );
  });

  // The registry's method of each installed plugin's type: the snapshot the
  // registry checked. A built-in AuthMethod is never mounted here, behind
  // the plugin gate.
  const methods = fastify.providerRegistry
    .authMethods()
    .filter((method) => fastify.authMethodPlugins.ofType(method.type) !== undefined);
  // No plugin loaded: no plugin route, and no hook.
  if (methods.length === 0) return;

  await fastify.register(async (scope) => {
    // Checked in `preParsing`, after the request ceiling (a route-level
    // `onRequest` hook) and before the body is read: a flood of requests to
    // an installed plugin's paths meets the rate limit before it reaches the
    // database.
    const refused = new WeakSet<FastifyRequest>();
    scope.addHook('preParsing', async (request, reply, payload) => {
      const type = routeType(request.routeOptions.url);
      const plugin = type === undefined ? undefined : scope.authMethodPlugins.ofType(type);
      if (
        plugin !== undefined &&
        (await authMethodPluginEnabledIn(scope, requestRealm(request).id, plugin))
      ) {
        return payload;
      }
      refused.add(request);
      // A path no route serves is answered before the limiter, with none of
      // its headers: the answer for an off plugin carries none either.
      for (const header of RATE_LIMIT_HEADERS) reply.removeHeader(header);
      return answerRouteNotFound(request, reply);
    });
    // A request refused above never reaches a handler, even when its client
    // closed the connection before the answer was written.
    scope.addHook('preHandler', async (request) => {
      if (refused.has(request)) {
        throw new Error(
          'A request to an AuthMethod plugin route the realm has off reached its handler'
        );
      }
    });
    for (const method of methods) mountAuthMethodRoutes(scope, method, host, { config });
  });
};

export default upstreamRoutes;
