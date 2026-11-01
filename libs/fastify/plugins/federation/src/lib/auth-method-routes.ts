import {
  type AuthMethod,
  type AuthMethodContext,
  AuthMethodContractError,
  AuthMethodFaultError,
  authMethodParameters,
  type AuthMethodRoute,
  authMethodRoutePrefix,
  authMethodTypeProblems,
  presentedUpstreamBinding,
  routeProblems,
  upstreamBindingMatches,
} from '@qauth-labs/server-federation';
import type { FastifyInstance, FastifyReply, FastifyRequest, FastifySchema } from 'fastify';
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
   * Read, without taking it, the pending transaction of `method` that the
   * request's flow cookie names: the `PendingUpstreamTransaction`
   * (`{ binding, transaction }`) stored from `startUpstreamStep`'s answer.
   * `undefined` or `null` when there is no flow cookie or no such
   * transaction; anything but such an object reads as none.
   *
   * The mount compares the callback's binding with this one before it calls
   * {@link takeTransaction}, so a request that does not carry the binding
   * (a cross-site callback, a forged one) leaves the pending sign-in alone.
   */
  peekTransaction(method: AuthMethod, request: FastifyRequest): Promise<unknown>;
  /**
   * Take the pending transaction of `method` that the request's flow cookie
   * names, once: the same `{ binding, transaction }` as
   * {@link peekTransaction}, and a second call for the same transaction
   * answers `undefined` (or `null`). `undefined` or `null` too when there is
   * no flow cookie or no such transaction. Anything but such an object reads
   * as no transaction.
   */
  takeTransaction(method: AuthMethod, request: FastifyRequest): Promise<unknown>;
  /**
   * Hand a callback's outcome, unchecked, to the engine
   * (`completeUpstreamStep`), which answers the request.
   *
   * The outcome is an `AuthMethodFaultError` when the method failed before it
   * had one: its handler threw, its bounce went somewhere it may not, or its
   * context could not be built (`contextFor` rejected, as with an
   * `AuthMethodConfigError`). `completeUpstreamStep` throws it, as it throws
   * any other fault of the method, so every fault ends the same way: the
   * generic error page and its trace id, never a raw 500.
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
  const problems = [...authMethodTypeProblems(type), ...routeProblems(routes)];
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
      // Not part of QAuth's API: a deployment's sign-in callbacks, which its
      // OpenAPI document does not list (#600).
      schema: hiddenFromOpenapi(),
      handler: async (request, reply) => handle(mounted, request, reply),
    });
  }
}

/**
 * The schema of a mounted route: `hide`, which `@fastify/swagger` reads to
 * leave a route out of the OpenAPI document. This lib does not depend on the
 * swagger plugin, whose types declare the member, hence the cast. A new
 * object per route: Fastify marks the schema object it compiles.
 */
const hiddenFromOpenapi = (): FastifySchema => ({ hide: true }) as unknown as FastifySchema;

/** The largest body a method's route reads, in bytes. */
const MAX_ROUTE_BODY_BYTES = 64 * 1024;

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
  const { method, route, host, type } = mounted;
  const seen = {
    method: route.method,
    query: authMethodParameters(request.query),
    form: authMethodParameters(
      route.method === 'POST' && isFormPost(request) ? request.body : undefined
    ),
  };

  if (route.kind === 'bounce') {
    // A bounce is handed no context: a cross-site POST that anyone can send
    // reaches it, so it holds no egress client and no signer.
    let location: string;
    try {
      location = bounceLocation(mounted, await route.handle(seen));
    } catch (error) {
      return host.complete(method, fault(type, 'the bounce route failed', error), request, reply);
    }
    reply.header('cache-control', 'no-store');
    return reply.redirect(location, 303);
  }

  // The host, not the method, binds a callback to its start: it compares the
  // binding the callback carries with the pending transaction's, in constant
  // time, BEFORE it takes the transaction. A forged callback, one forwarded
  // to another browser, a replay, or a cross-site request that does not
  // carry the binding ends here as transaction_mismatch: the method never
  // runs, and the pending sign-in stays pending, so another site cannot
  // cancel it.
  const mismatch = () =>
    host.complete(method, { kind: 'failed', reason: 'transaction_mismatch' }, request, reply);
  const presented = presentedUpstreamBinding(route, seen);
  if (!bindingMatches(await host.peekTransaction(method, request), presented)) {
    return mismatch();
  }
  const taken = await host.takeTransaction(method, request);
  // Again on what was taken: another start in the same browser may have
  // replaced the transaction between the two reads.
  if (!bindingMatches(taken, presented)) return mismatch();
  // A stored transaction is always an object (`startUpstreamStep` refuses
  // anything else); `null` is a cache's "no such key".
  const transaction = (taken as { transaction?: unknown }).transaction;
  if (typeof transaction !== 'object' || transaction === null) return mismatch();
  // The transaction is spent from here on: whatever goes wrong now ends the
  // step through the engine, never as an error that escapes the route.
  let context: AuthMethodContext;
  try {
    context = await host.contextFor(method, request);
  } catch (error) {
    return host.complete(
      method,
      fault(type, "the method's context could not be built", error),
      request,
      reply
    );
  }
  let outcome: unknown;
  try {
    outcome = await route.handle({ ...seen, transaction }, context);
  } catch (error) {
    outcome = fault(type, 'the callback route threw', error);
  }
  return host.complete(method, outcome, request, reply);
}

/** Whether `pending` is a stored transaction whose binding `presented` is. */
function bindingMatches(pending: unknown, presented: string | undefined): boolean {
  if (typeof pending !== 'object' || pending === null) return false;
  return upstreamBindingMatches((pending as { binding?: unknown }).binding, presented);
}

/** `error` as a fault of the method: itself when it already is one, else wrapped. */
function fault(type: string, problem: string, error: unknown): AuthMethodFaultError {
  return error instanceof AuthMethodFaultError && error.methodType === type
    ? error
    : new AuthMethodFaultError(type, problem, { cause: error });
}

/** Whether a POST carries a form: a provider's `form_post` is urlencoded. */
function isFormPost(request: FastifyRequest): boolean {
  const type = request.headers['content-type'];
  return typeof type === 'string' && /^application\/x-www-form-urlencoded\s*(?:;|$)/i.test(type);
}

/**
 * Where a bounce sends the browser: one of the method's own `GET` callback
 * routes, on the same origin, with a query that is a plain object of
 * strings.
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
  if (!isPlainObject(query) || !Object.values(query).every((value) => typeof value === 'string')) {
    throw new AuthMethodFaultError(
      mounted.type,
      'a bounce carried a query that is not a plain object of strings'
    );
  }
  const search = new URLSearchParams(query as Record<string, string>).toString();
  return search === ''
    ? `${mounted.prefix}${target.path}`
    : `${mounted.prefix}${target.path}?${search}`;
}

/** An object with the plain prototype or none: not a list, not a class instance. */
function isPlainObject(value: unknown): value is object {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value) as unknown;
  return prototype === Object.prototype || prototype === null;
}
