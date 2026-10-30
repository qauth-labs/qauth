import { randomUUID } from 'node:crypto';

import rateLimit from '@fastify/rate-limit';
import swagger, { type FastifyDynamicSwaggerOptions } from '@fastify/swagger';
import { TooManyRequestsError } from '@qauth-labs/shared-errors';
import Fastify, {
  type FastifyBaseLogger,
  type FastifyInstance,
  type FastifyPluginAsync,
  LogController,
} from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';

import { env } from '../../config/env';
import { API_FAMILY_PREFIXES } from '../api-conventions/families';
import type { OperationRegistry } from '../helpers/admin-operations';
import { adminAddressRateLimitKey, adminSubjectRateLimitKey } from '../helpers/realm-rate-limit';
import {
  answerClientError,
  answerFrameworkError,
  answerRouteNotFound,
  answerUnknownRouteBeforeBody,
  requestDeadlineOptions,
} from '../helpers/request-bounds';
import { openapiOptions } from '../openapi-options';
import { DEFAULT_ADMIN_RATE_LIMIT } from '../plugins/admin-operations';
import errorHandler from '../plugins/error-handler';
import { requestIdPlugin } from '../plugins/request-id';
import { securityHeadersPlugin } from '../plugins/security-headers';
import { AdminCallsInFlight, adminPipeline, type AdminRateLimitStage } from './pipeline';

/**
 * THE ADMIN LISTENER (ADR-019 Decisions 7 and 8, issue #511).
 *
 * The admin API runs on its own Fastify instance, a second HTTP server of the
 * process, bound to ADMIN_API_HOST and ADMIN_API_PORT (loopback by default),
 * on a process that holds the `admin` service role with ADMIN_API_ENABLED on.
 * Its routes register only there: the public listener refuses to boot an
 * admin route and answers 404 for every admin path.
 *
 * `main.ts` builds the instance with {@link createAdminServer}, hands it to
 * the app, and listens on it once the app is ready. The app installs the
 * admin API on it with {@link installAdminApi}, sharing its own database,
 * cache, signer and JWT decorators, and closes it with the public listener.
 *
 * The listener grants nothing for a caller's network position: every route
 * sits behind the admin pipeline (`./pipeline.ts`), whose first stage refuses
 * a call without an admin token. The one exception is its OpenAPI document,
 * which describes the routes and holds no realm data.
 */

/** The admin API's OpenAPI document, served on the admin listener only. */
export const ADMIN_OPENAPI_PATH = `${API_FAMILY_PREFIXES.admin}/openapi.json`;

/**
 * The route modules of the admin API, each registered behind the pipeline.
 * None ships yet: the first operations, reading a realm and updating its
 * policies, arrive with #517.
 */
export const ADMIN_ROUTE_MODULES: readonly FastifyPluginAsync[] = Object.freeze([]);

/**
 * The OpenAPI options of the admin listener: the server's own (#347), so the
 * admin document carries the same `Problem` schema, error responses and
 * extensions, under the admin API's title.
 */
export const adminOpenapiOptions: FastifyDynamicSwaggerOptions = {
  ...openapiOptions,
  openapi: {
    ...openapiOptions.openapi,
    info: {
      title: 'QAuth Admin API',
      description:
        'The admin API of QAuth (ADR-019 Decision 7), served on the internal admin listener only. Every operation needs an admin token whose account holds a grant on the realm in the path; a security operation also needs an approval bound to it.',
      version: '1.0.0',
    },
  },
};

/**
 * The id of an admin request: always one the server makes, never the
 * caller's. The audit row records it as its `trace_id`, in an append-only
 * log, so a caller cannot choose it, reuse another request's, or make it
 * longer than the column. It is echoed in REQUEST_ID_HEADER and every problem
 * document, so a caller still learns it.
 */
export function adminRequestId(): string {
  return randomUUID();
}

/** Options for {@link createAdminServer}. */
export interface AdminServerOptions {
  /** The logger the listener writes to: in `main.ts`, the public server's, as a child. */
  readonly loggerInstance?: FastifyBaseLogger;
}

/**
 * Build the admin listener's Fastify instance, with the server-wide rules of
 * `main.ts`'s public instance:
 *
 * - the Zod validator and serializer compilers, set before any route, so ajv
 *   (and with it `fast-uri`) never validates an admin request;
 * - HTTP/1.1 only;
 * - REQUEST_TIMEOUT_MS bounds an unfinished request;
 * - an unknown path is answered before its body is read, with the
 *   `not_found` problem document, and the router's refusals and unreadable
 *   requests answer problem documents too;
 * - every request has an id the server made ({@link adminRequestId});
 * - no proxy is trusted: `request.ip`, which keys the per-address ceiling, is
 *   the TCP peer. `TRUST_PROXY` names the public listener's proxies, and a
 *   caller in that range could otherwise pick a new address per request with
 *   `X-Forwarded-For` and escape the ceiling.
 *
 * No HEAD route is added for a GET route: the admin API serves none.
 */
export function createAdminServer(options: AdminServerOptions = {}): FastifyInstance {
  const server = Fastify({
    ...(options.loggerInstance === undefined
      ? { logger: false }
      : { loggerInstance: options.loggerInstance }),
    requestIdHeader: false,
    genReqId: adminRequestId,
    logController: new LogController({ requestIdLogLabel: 'reqId' }),
    trustProxy: false,
    routerOptions: { ignoreTrailingSlash: true },
    exposeHeadRoutes: false,
    ...requestDeadlineOptions(env.REQUEST_TIMEOUT_MS),
    frameworkErrors: answerFrameworkError,
    clientErrorHandler: answerClientError,
  }).withTypeProvider<ZodTypeProvider>();
  // The listener makes every request id itself (`adminRequestId`), so
  // Fastify's `requestIdHeader` stays unset: the root's own answers echo the
  // id in this header instead.
  server.decorate('requestIdEchoHeader', env.REQUEST_ID_HEADER);
  server.setValidatorCompiler(validatorCompiler);
  server.setSerializerCompiler(serializerCompiler);
  server.addHook('onRequest', answerUnknownRouteBeforeBody);
  server.setNotFoundHandler(answerRouteNotFound);
  // A PATCH body of the admin API is a JSON Merge Patch (API conventions).
  server.addContentTypeParser(
    'application/merge-patch+json',
    { parseAs: 'string' },
    server.getDefaultJsonParser('error', 'error')
  );
  return server;
}

/**
 * How long the admin listener waits for its calls in flight when the server
 * closes, before it closes their connections: under the 10 s Fastify gives a
 * `preClose` hook, so the server's own close never times out.
 */
export const ADMIN_CLOSE_GRACE_MS = 8_000;

/**
 * How long a closing admin listener may take in all: after the grace, it
 * waits for the audit rows of the calls whose connections it closed, until
 * then and no longer, still under the 10 s of the `preClose` hook.
 */
export const ADMIN_CLOSE_BUDGET_MS = 9_500;

/** How often a closing admin listener closes the connections that went idle. */
const IDLE_SWEEP_MS = 50;

/**
 * Close the admin listener: it takes no new call, lets each call in flight
 * finish, and resolves once every connection is closed. A keep-alive
 * connection would hold the close open once its last answer is sent, until
 * the client let it go, so each connection is closed as soon as it is idle,
 * and any still open after {@link ADMIN_CLOSE_GRACE_MS} is closed then.
 *
 * Closing a connection does not stop its call: the handler runs on, and its
 * audit row still needs the database. So the close then waits, up to
 * {@link ADMIN_CLOSE_BUDGET_MS} from its start, until no call owes a row
 * (`calls`), and logs the calls that still do.
 */
export async function closeAdminServer(
  admin: FastifyInstance,
  calls?: AdminCallsInFlight
): Promise<void> {
  const started = Date.now();
  const closing = admin.close();
  const sweep = setInterval(() => admin.server.closeIdleConnections(), IDLE_SWEEP_MS);
  const deadline = setTimeout(() => admin.server.closeAllConnections(), ADMIN_CLOSE_GRACE_MS);
  try {
    await closing;
  } finally {
    clearInterval(sweep);
    clearTimeout(deadline);
  }
  if (calls === undefined) return;
  if (!(await calls.drained(Math.max(0, started + ADMIN_CLOSE_BUDGET_MS - Date.now())))) {
    admin.log.warn(
      { calls: calls.size },
      'The admin listener closed while calls still owed their audit rows: rows not written yet are lost'
    );
  }
}

/** Options for {@link installAdminApi}. */
export interface AdminApiOptions {
  /**
   * TEST SUPPORT — the operation registry the pipeline classifies against.
   * The server's own when unset, which `main.ts` never sets.
   */
  readonly registry?: OperationRegistry;
  /**
   * TEST SUPPORT — routes registered behind the pipeline beside the admin
   * API's own, such as a fixture operation. `main.ts` never sets it.
   */
  readonly routes?: (scope: FastifyInstance) => void | Promise<void>;
}

/** The Redis key prefix of the listener's ceilings, apart from the public listener's. */
const ADMIN_RATE_LIMIT_NAMESPACE = 'qauth-admin-rate-limit-';

/** A request ceiling of the listener, from a `createRateLimit` check. */
function ceilingStage(check: ReturnType<FastifyInstance['createRateLimit']>): AdminRateLimitStage {
  return async (request, reply) => {
    const result = await check(request);
    if (result.isAllowed || !result.isExceeded) return;
    reply.header('retry-after', String(result.ttlInSeconds));
    throw new TooManyRequestsError();
  };
}

/**
 * The listener's two request ceilings: one per client address, run first on
 * every route of the listener, and one per token subject, which the pipeline
 * runs right after its token guard. Each refuses before the realm is read, so
 * a refused call writes no audit row.
 *
 * With RATE_LIMIT_ENABLED on, each allows RATE_LIMIT_MAX calls per
 * RATE_LIMIT_WINDOW, counted in the server's Redis under a prefix of their
 * own. With it off, the listener still keeps both, in memory, at the
 * classification stage's default ceiling (`DEFAULT_ADMIN_RATE_LIMIT`, #508):
 * every admin route authorizes, so none runs without one.
 */
async function registerCeilings(
  admin: FastifyInstance,
  source: FastifyInstance
): Promise<{ byAddress: AdminRateLimitStage; bySubject: AdminRateLimitStage }> {
  const limits = env.RATE_LIMIT_ENABLED
    ? { max: env.RATE_LIMIT_MAX, timeWindow: env.RATE_LIMIT_WINDOW * 1000 }
    : { max: DEFAULT_ADMIN_RATE_LIMIT.max, timeWindow: DEFAULT_ADMIN_RATE_LIMIT.timeWindow };
  await admin.register(rateLimit, {
    global: false,
    ...(env.RATE_LIMIT_ENABLED ? { redis: source.redis } : {}),
    nameSpace: ADMIN_RATE_LIMIT_NAMESPACE,
    ...limits,
  });
  return {
    byAddress: ceilingStage(
      admin.createRateLimit({ ...limits, keyGenerator: adminAddressRateLimitKey })
    ),
    bySubject: ceilingStage(
      admin.createRateLimit({ ...limits, keyGenerator: adminSubjectRateLimitKey })
    ),
  };
}

/**
 * Install the admin API on `admin`, the instance {@link createAdminServer}
 * built, from `source`, the app scope that registered the database, cache,
 * signer, DPoP and JWT plugins: the listener shares their decorators, so one
 * pool, one Redis client and one signer serve both listeners.
 *
 * In order: the shared decorators; the error handler of the app, so every
 * error is a problem document; the request id; the OpenAPI collector; the
 * security headers; the per-address ceiling; the pipeline with the routes
 * behind it; and the OpenAPI document, last, outside the pipeline.
 *
 * `admin` stops accepting requests when `source` begins to close, before the
 * database closes: its `preClose` hook closes it ({@link closeAdminServer}).
 */
export async function installAdminApi(
  admin: FastifyInstance,
  source: FastifyInstance,
  options: AdminApiOptions = {}
): Promise<void> {
  admin.decorate('db', source.db);
  admin.decorate('dbPool', source.dbPool);
  admin.decorate('repositories', source.repositories);
  admin.decorate('redis', source.redis);
  admin.decorate('signer', source.signer);
  admin.decorate('dpop', source.dpop);
  admin.decorate('jwtUtils', source.jwtUtils);
  admin.decorate('verifyRequestAccessToken', source.verifyRequestAccessToken);
  // The realm of a request: the one its token's issuer names while the token
  // guard runs, then the one its path names. Never a host's.
  admin.decorateRequest('realm', null);
  admin.decorateRequest('realmHost', null);

  await admin.register(errorHandler);
  await admin.register(requestIdPlugin);
  await admin.register(swagger, adminOpenapiOptions);
  await admin.register(securityHeadersPlugin);

  const ceilings = await registerCeilings(admin, source);
  admin.addHook('onRequest', ceilings.byAddress);

  const calls = new AdminCallsInFlight();
  await admin.register(adminPipeline, {
    ...(options.registry === undefined ? {} : { registry: options.registry }),
    bySubject: ceilings.bySubject,
    calls,
    routes: async (scope) => {
      for (const module of ADMIN_ROUTE_MODULES) await scope.register(module);
      await options.routes?.(scope);
    },
  });

  admin.get(ADMIN_OPENAPI_PATH, { schema: { hide: true } }, async () => admin.swagger());

  source.addHook('preClose', async () => {
    await closeAdminServer(admin, calls);
  });
}
