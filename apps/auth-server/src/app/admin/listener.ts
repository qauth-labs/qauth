import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';

import rateLimit from '@fastify/rate-limit';
import swagger, { type FastifyDynamicSwaggerOptions } from '@fastify/swagger';
import { TooManyRequestsError } from '@qauth-labs/shared-errors';
import Fastify, {
  type FastifyBaseLogger,
  type FastifyInstance,
  type FastifyPluginAsync,
  type FastifyRequest,
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
import { clientAddressKey } from '../helpers/client-address';
import {
  answerClientError,
  answerFrameworkError,
  answerRouteNotFound,
  answerUnknownRouteBeforeBody,
  requestDeadlineOptions,
} from '../helpers/request-bounds';
import { openapiOptions } from '../openapi-options';
import errorHandler from '../plugins/error-handler';
import { requestIdPlugin } from '../plugins/request-id';
import { securityHeadersPlugin } from '../plugins/security-headers';
import { adminPipeline, type AdminRateLimitStage } from './pipeline';

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

/** A request id a caller may set: what the audit log's `trace_id` column holds. */
const CALLER_REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;

/**
 * The id of an admin request: the caller's own, from REQUEST_ID_HEADER, when
 * it is a short token of safe characters, so a proxy's id still correlates;
 * otherwise a fresh UUID. The audit row records it as its `trace_id`, which
 * holds at most 128 characters, so a longer or stranger value never reaches it.
 */
export function adminRequestId(raw: IncomingMessage): string {
  const given = raw.headers[env.REQUEST_ID_HEADER.toLowerCase()];
  return typeof given === 'string' && CALLER_REQUEST_ID.test(given) ? given : randomUUID();
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
 * - `TRUST_PROXY` decides `request.ip`, which keys the per-address ceiling.
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
    trustProxy: env.TRUST_PROXY,
    routerOptions: { ignoreTrailingSlash: true },
    exposeHeadRoutes: false,
    ...requestDeadlineOptions(env.REQUEST_TIMEOUT_MS),
    frameworkErrors: answerFrameworkError,
    clientErrorHandler: answerClientError,
  }).withTypeProvider<ZodTypeProvider>();
  // The listener reads the caller's request id itself (`adminRequestId`), so
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

/** A request ceiling of the listener, from a `createRateLimit` check. */
function ceilingStage(check: ReturnType<FastifyInstance['createRateLimit']>): AdminRateLimitStage {
  return async (request, reply) => {
    const result = await check(request);
    if (result.isAllowed || !result.isExceeded) return;
    reply.header('retry-after', String(result.ttlInSeconds));
    throw new TooManyRequestsError();
  };
}

/** The account a request's token names, as the admin token guard verified it. */
function subjectKey(request: FastifyRequest): string {
  const issuer = request.jwtPayload?.iss;
  const subject = request.jwtPayload?.sub;
  if (issuer === undefined || subject === undefined) {
    throw new Error('The per-subject ceiling runs after the token guard');
  }
  return `admin:subject:${issuer}:${subject}`;
}

/**
 * The listener's two request ceilings (RATE_LIMIT_MAX per RATE_LIMIT_WINDOW
 * each), with the server's rate limiter over its Redis: one per client
 * address, run first on every route of the listener, and one per token
 * subject, which the pipeline runs right after its token guard. Neither when
 * RATE_LIMIT_ENABLED is off; the classification stage then keeps a ceiling of
 * its own on every admin route.
 */
async function registerCeilings(
  admin: FastifyInstance,
  source: FastifyInstance
): Promise<{ byAddress: AdminRateLimitStage; bySubject: AdminRateLimitStage } | undefined> {
  if (!env.RATE_LIMIT_ENABLED) return undefined;
  const limits = { max: env.RATE_LIMIT_MAX, timeWindow: env.RATE_LIMIT_WINDOW * 1000 };
  await admin.register(rateLimit, { global: false, redis: source.redis, ...limits });
  return {
    byAddress: ceilingStage(
      admin.createRateLimit({
        ...limits,
        keyGenerator: (request) => `admin:address:${clientAddressKey(request)}`,
      })
    ),
    bySubject: ceilingStage(admin.createRateLimit({ ...limits, keyGenerator: subjectKey })),
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
 * database closes: its `preClose` hook closes it.
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
  if (ceilings !== undefined) admin.addHook('onRequest', ceilings.byAddress);

  await admin.register(adminPipeline, {
    ...(options.registry === undefined ? {} : { registry: options.registry }),
    ...(ceilings === undefined ? {} : { bySubject: ceilings.bySubject }),
    routes: async (scope) => {
      for (const module of ADMIN_ROUTE_MODULES) await scope.register(module);
      await options.routes?.(scope);
    },
  });

  admin.get(ADMIN_OPENAPI_PATH, { schema: { hide: true } }, async () => admin.swagger());

  source.addHook('preClose', async () => {
    await admin.close();
  });
}
