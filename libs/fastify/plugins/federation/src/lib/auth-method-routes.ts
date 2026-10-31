import {
  type AuthMethod,
  type AuthMethodContext,
  AuthMethodContractError,
  AuthMethodFaultError,
  type AuthMethodParameters,
  type AuthMethodRoute,
  authMethodRoutePrefix,
  routeProblems,
} from '@qauth-labs/server-federation';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import fp from 'fastify-plugin';

import packageJson from '../../package.json';

/**
 * Mounting an AuthMethod's routes (#599, EXPERIMENTAL): each method's routes go
 * under its own prefix, `/upstream/<type>`, on the realm host, and nowhere
 * else.
 *
 * A method never touches Fastify. It declares its routes as data (a kind, a
 * method, a path below its prefix, a handler), and this module registers them.
 * So a method cannot register a route outside its prefix, add a hook, read a
 * header or a cookie, or answer a request itself: the path is checked again
 * here, the handler sees only the query and the form, and the answer is either
 * an outcome the engine acts on or a bounce to one of the method's own `GET`
 * routes.
 *
 * Every route is a `browser` route (`apps/auth-server/src/app/helpers/route-surface.ts`):
 * it answers on the realm's primary host only, where the flow cookie lives.
 *
 * @experimental
 */

/**
 * What the sign-in engine supplies to the mounted routes. The plugin runtime
 * (#600) builds contexts; the upstream sign-in flow (#639) keeps transactions
 * and acts on outcomes.
 *
 * @experimental
 */
export interface AuthMethodRouteHost {
  /**
   * The method's context for the realm the request was resolved to: its
   * config, egress, signer and logger (`createAuthMethodContext`).
   */
  contextFor(method: AuthMethod, request: FastifyRequest): Promise<AuthMethodContext>;
  /**
   * Take the pending transaction of `method` that the request's flow cookie
   * names, once: a second call for the same transaction answers `undefined`.
   * `undefined` too when there is no flow cookie or no such transaction.
   */
  takeTransaction(method: AuthMethod, request: FastifyRequest): Promise<unknown>;
  /**
   * Hand a callback's outcome, unchecked, to the engine
   * (`completeUpstreamStep`), which answers the request.
   */
  complete(
    method: AuthMethod,
    outcome: unknown,
    request: FastifyRequest,
    reply: FastifyReply
  ): Promise<unknown>;
}

/**
 * Options of {@link authMethodRoutesPlugin}.
 *
 * @experimental
 */
export interface AuthMethodRoutesOptions {
  readonly host: AuthMethodRouteHost;
}

/**
 * Mount the routes of every AuthMethod in `fastify.providerRegistry`, each
 * under `/upstream/<type>`. Register it after `federationPlugin`.
 *
 * @experimental
 */
export const authMethodRoutesPlugin = fp<AuthMethodRoutesOptions>(
  async (fastify, options) => {
    for (const method of fastify.providerRegistry.authMethods()) {
      mountAuthMethodRoutes(fastify, method, options.host);
    }
  },
  { name: `${packageJson.name}/auth-method-routes`, dependencies: [packageJson.name] }
);

/**
 * Mount one method's routes under `/upstream/<type>`.
 *
 * @throws AuthMethodContractError when a route's path could leave the prefix,
 *   or another route problem the registry checks (a method mounted without
 *   going through the registry is checked here all the same)
 * @experimental
 */
export function mountAuthMethodRoutes(
  fastify: FastifyInstance,
  method: AuthMethod,
  host: AuthMethodRouteHost
): void {
  const problems = routeProblems(method.routes);
  if (problems.length > 0) {
    throw new AuthMethodContractError(`The AuthMethod ${method.type}`, problems);
  }
  const prefix = authMethodRoutePrefix(method.type);
  // `as const`: the auth server types `surface` as its RouteSurface union.
  const config = { surface: 'browser' as const };

  for (const route of method.routes) {
    const url = `${prefix}${route.path}`;
    // The path pattern already rules out dot segments and encodings; this
    // checks the joined URL the way a router would read it, once more.
    if (!url.startsWith(`${prefix}/`) || new URL(url, 'https://realm.invalid').pathname !== url) {
      throw new AuthMethodContractError(`The AuthMethod ${method.type}`, [
        `${route.method} ${route.path} would leave ${prefix}`,
      ]);
    }
    fastify.route({
      method: route.method,
      url,
      config,
      // No HEAD twin: a HEAD request would run the callback and take the
      // transaction without ever showing the person the outcome.
      exposeHeadRoute: false,
      handler: async (request, reply) => handle(method, route, prefix, host, request, reply),
    });
  }
}

async function handle(
  method: AuthMethod,
  route: AuthMethodRoute,
  prefix: string,
  host: AuthMethodRouteHost,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<unknown> {
  const context = await host.contextFor(method, request);
  const seen = {
    method: route.method,
    query: parametersOf(request.query),
    form: route.method === 'POST' ? parametersOf(request.body) : Object.freeze({}),
  };

  if (route.kind === 'bounce') {
    const bounce: unknown = await route.handle(seen, context);
    reply.header('cache-control', 'no-store');
    return reply.redirect(bounceLocation(method, prefix, bounce), 303);
  }

  const transaction = await host.takeTransaction(method, request);
  const outcome: unknown = await route.handle({ ...seen, transaction }, context);
  return host.complete(method, outcome, request, reply);
}

/**
 * Where a bounce sends the browser: one of the method's own `GET` routes, on
 * the same origin, with string query members only.
 */
function bounceLocation(method: AuthMethod, prefix: string, bounce: unknown): string {
  const { to, query } = (typeof bounce === 'object' && bounce !== null ? bounce : {}) as {
    to?: unknown;
    query?: unknown;
  };
  const target = method.routes.find((route) => route.method === 'GET' && route.path === to);
  if (target === undefined) {
    throw new AuthMethodFaultError(
      method.type,
      "a bounce went somewhere other than the method's own GET routes"
    );
  }
  if (
    typeof query !== 'object' ||
    query === null ||
    !Object.values(query).every((value) => typeof value === 'string')
  ) {
    throw new AuthMethodFaultError(
      method.type,
      'a bounce carried a query that is not a map of strings'
    );
  }
  const search = new URLSearchParams(query as Record<string, string>).toString();
  return search === '' ? `${prefix}${target.path}` : `${prefix}${target.path}?${search}`;
}

/** The string and string-list members of a parsed query or form, frozen. */
function parametersOf(value: unknown): AuthMethodParameters {
  // No prototype: a parameter named `__proto__` stays a parameter.
  const parameters = Object.create(null) as Record<string, string | readonly string[]>;
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    for (const [name, member] of Object.entries(value)) {
      if (typeof member === 'string') parameters[name] = member;
      else if (Array.isArray(member) && member.every((item) => typeof item === 'string')) {
        parameters[name] = Object.freeze([...(member as string[])]);
      }
    }
  }
  return Object.freeze(parameters);
}
