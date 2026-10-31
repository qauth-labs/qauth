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
  // One snapshot of what the method declared, checked and then used for every
  // request: a method that changes its members later changes nothing here.
  const type = method.type;
  const routes = Object.freeze([...method.routes]);
  const problems = routeProblems(routes);
  if (problems.length > 0) {
    throw new AuthMethodContractError(`The AuthMethod ${type}`, problems);
  }
  const prefix = authMethodRoutePrefix(type);
  // `as const`: the auth server types `surface` as its RouteSurface union.
  const config = { surface: 'browser' as const };

  for (const route of routes) {
    const url = `${prefix}${route.path}`;
    // The path pattern already rules out dot segments and encodings; this
    // checks the joined URL the way a router would read it, once more.
    if (!url.startsWith(`${prefix}/`) || new URL(url, 'https://realm.invalid').pathname !== url) {
      throw new AuthMethodContractError(`The AuthMethod ${type}`, [
        `${route.method} ${route.path} would leave ${prefix}`,
      ]);
    }
    const mounted: MountedMethod = { method, type, prefix, routes, route, host };
    fastify.route({
      method: route.method,
      url,
      config,
      bodyLimit: MAX_ROUTE_BODY_BYTES,
      // No HEAD twin: a HEAD request would run the callback and take the
      // transaction without ever showing the person the outcome.
      exposeHeadRoute: false,
      handler: async (request, reply) => handle(mounted, request, reply),
    });
  }
}

/** The largest body a method's route reads, in bytes. */
const MAX_ROUTE_BODY_BYTES = 64 * 1024;
/** The most parameters a method sees from one query or form; the rest are dropped. */
const MAX_PARAMETERS = 64;
/** The longest parameter value a method sees; a longer one is dropped. */
const MAX_PARAMETER_LENGTH = 8192;
/** The most values of one repeated parameter a method sees; more drops the parameter. */
const MAX_PARAMETER_VALUES = 16;

/** One route as mounted: the method's snapshot and the host. */
interface MountedMethod {
  readonly method: AuthMethod;
  readonly type: string;
  readonly prefix: string;
  readonly routes: readonly AuthMethodRoute[];
  readonly route: AuthMethodRoute;
  readonly host: AuthMethodRouteHost;
}

async function handle(
  mounted: MountedMethod,
  request: FastifyRequest,
  reply: FastifyReply
): Promise<unknown> {
  const { method, route, host } = mounted;
  const seen = {
    method: route.method,
    query: parametersOf(request.query),
    form:
      route.method === 'POST' && isFormPost(request)
        ? parametersOf(request.body)
        : (Object.freeze(Object.create(null)) as AuthMethodParameters),
  };

  if (route.kind === 'bounce') {
    const bounce: unknown = await route.handle(seen, await host.contextFor(method, request));
    reply.header('cache-control', 'no-store');
    return reply.redirect(bounceLocation(mounted, bounce), 303);
  }

  // The host, not the method, refuses a callback with no pending transaction:
  // a forged callback, one forwarded to another browser, a replay. The method
  // never runs for it, so it never spends the code or calls the provider.
  const transaction = await host.takeTransaction(method, request);
  if (transaction === undefined) {
    return host.complete(
      method,
      { kind: 'failed', reason: 'transaction_mismatch' },
      request,
      reply
    );
  }
  const context = await host.contextFor(method, request);
  const outcome: unknown = await route.handle({ ...seen, transaction }, context);
  return host.complete(method, outcome, request, reply);
}

/** Whether a POST carries a form: a provider's `form_post` is urlencoded. */
function isFormPost(request: FastifyRequest): boolean {
  const type = request.headers['content-type'];
  return typeof type === 'string' && /^application\/x-www-form-urlencoded\s*(?:;|$)/i.test(type);
}

/**
 * Where a bounce sends the browser: one of the method's own `GET` callback
 * routes, on the same origin, with string query members only.
 */
function bounceLocation(mounted: MountedMethod, bounce: unknown): string {
  const { to, query } = (typeof bounce === 'object' && bounce !== null ? bounce : {}) as {
    to?: unknown;
    query?: unknown;
  };
  const target = mounted.routes.find(
    (route) => route.kind === 'callback' && route.method === 'GET' && route.path === to
  );
  if (target === undefined) {
    throw new AuthMethodFaultError(
      mounted.type,
      "a bounce went somewhere other than the method's own GET callback routes"
    );
  }
  if (
    typeof query !== 'object' ||
    query === null ||
    !Object.values(query).every((value) => typeof value === 'string')
  ) {
    throw new AuthMethodFaultError(
      mounted.type,
      'a bounce carried a query that is not a map of strings'
    );
  }
  const search = new URLSearchParams(query as Record<string, string>).toString();
  return search === ''
    ? `${mounted.prefix}${target.path}`
    : `${mounted.prefix}${target.path}?${search}`;
}

/**
 * The string and string-list members of a parsed query or form, within the
 * caps, frozen. Anything else is dropped: a method that misses a parameter it
 * needs refuses the request.
 */
function parametersOf(value: unknown): AuthMethodParameters {
  // No prototype: a parameter named `__proto__` stays a parameter.
  const parameters = Object.create(null) as Record<string, string | readonly string[]>;
  if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
    let count = 0;
    for (const [name, member] of Object.entries(value)) {
      if (count >= MAX_PARAMETERS) break;
      if (typeof member === 'string') {
        if (member.length > MAX_PARAMETER_LENGTH) continue;
        parameters[name] = member;
        count += 1;
      } else if (
        Array.isArray(member) &&
        member.length <= MAX_PARAMETER_VALUES &&
        member.every((item) => typeof item === 'string' && item.length <= MAX_PARAMETER_LENGTH)
      ) {
        parameters[name] = Object.freeze([...(member as string[])]);
        count += 1;
      }
    }
  }
  return Object.freeze(parameters);
}
