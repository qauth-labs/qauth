import { randomUUID } from 'node:crypto';

import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import { awaitDatabaseMigrations } from '@qauth-labs/fastify-plugin-db';
import Fastify, { LogController } from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';

import { app } from './app/app';
import {
  answerClientError,
  answerFrameworkError,
  answerRouteNotFound,
  answerUnknownRouteBeforeBody,
  requestDeadlineOptions,
} from './app/helpers/request-bounds';
import { openapiOptions } from './app/openapi-options';
import errorHandler from './app/plugins/error-handler';
import { env, envDeprecationWarnings, envExperimentalWarnings } from './config/env';
import { buildLoggerOptions } from './config/logger';

// Instantiate Fastify with structured logging + request-id tracking.
//
// - `logger`: pino with secret redaction and (optionally) pino-pretty in dev
//   (#122). `LOG_LEVEL` is honoured via `buildLoggerOptions`.
// - `genReqId` / `requestIdHeader`: a request id is taken from the inbound
//   `REQUEST_ID_HEADER` when present and otherwise generated, then attached to
//   the request-scoped logger as `reqId` so every log line for a request is
//   correlated. The id is echoed back on the response by the request-id plugin
//   (#128). The label is set through `logController` rather than the top-level
//   `requestIdLogLabel`, which Fastify 5 deprecated (FSTDEP024) and removes in
//   Fastify 6.
//
// SECURITY INVARIANT — HTTP/1.1 only. Do NOT add `http2: true` (or `http2SessionTimeout`,
// or an HTTP/2 `serverFactory`) here without first clearing the `find-my-way` advisory.
// Fastify's router is `find-my-way`, and CVE-2026-47219 (DoS) is HTTP/2-specific; serving
// HTTP/1.1 is the only reason it is inert. The `find-my-way: '>=9.7.0'` floor in
// `pnpm-workspace.yaml` guards this, so an HTTP/2 switch is safe only as long as that floor
// (or a later fixed version) is what actually resolves — verify with `pnpm why find-my-way`.
const server = Fastify({
  logger: buildLoggerOptions(env),
  requestIdHeader: env.REQUEST_ID_HEADER,
  logController: new LogController({ requestIdLogLabel: 'reqId' }),
  genReqId: () => randomUUID(),
  // Which reverse-proxy hops may set `request.ip` (validated TRUST_PROXY: off
  // by default, or the proxies' addresses/CIDRs — never `true` or a hop count).
  // Every per-IP rate limit and the `ip:` failed-login lockout key on
  // `request.ip` (an IPv6 client by its /64; app/helpers/client-address.ts);
  // behind a proxy with this unset, all callers share one bucket. The same list
  // decides `request.host`, which picks the request's realm
  // (app/plugins/realm-resolver.ts, #486): `X-Forwarded-Host` counts only from
  // a listed hop. The host only selects a realm; no URL is built from it, and
  // nothing reads `request.protocol`. Every public URL starts at the issuer of
  // the resolved realm (app/helpers/realm-url.ts, #490), and the lint
  // configuration refuses the request's authority outside the resolver.
  trustProxy: env.TRUST_PROXY,
  routerOptions: {
    ignoreTrailingSlash: true,
  },
  // A request body is buffered until it is complete. Bound how long it may stay
  // incomplete (REQUEST_TIMEOUT_MS, 60 s by default): Fastify's default is for
  // ever, which let a caller park unfinished requests until the heap ran out.
  ...requestDeadlineOptions(env.REQUEST_TIMEOUT_MS),
  // A request the router refuses before any route (a path that is not valid
  // percent-encoding, an over-long path parameter) and a connection whose
  // request cannot be read at all answer problem documents too, not
  // Fastify's own envelope (#513).
  frameworkErrors: answerFrameworkError,
  clientErrorHandler: answerClientError,
}).withTypeProvider<ZodTypeProvider>();

// Answer a request for an unknown route BEFORE its body is read. The default 404
// belongs to this root instance, outside the scope `app.ts` registers the rate
// limiter in, yet Fastify still parses its body, so it buffered bodies for anyone
// at any rate. Same answer and log line as Fastify's own handler.
server.addHook('onRequest', answerUnknownRouteBeforeBody);

// The root instance's own answers are problem documents too (#513): a route
// registered here rather than in the app, such as the Swagger UI's static
// files under `/docs` (`ENABLE_SWAGGER`), and `reply.callNotFound()` from one,
// would otherwise answer Fastify's `{ message, error, statusCode }` envelope.
// The not-found handler is the document of a path no route serves; the error
// handler is the app's own (`app/plugins/error-handler.ts`), registered on the
// root as well, since the app's copy covers only the app's scope.
server.setNotFoundHandler(answerRouteNotFound);

// Set up Zod validator and serializer.
//
// SECURITY INVARIANT — this global Zod validator compiler is load-bearing beyond typing.
// It replaces Fastify's default `ajv` compiler for *every* route, and `ajv` is what pulls
// `fast-uri`, which carries two unfixed-in-tree host-confusion advisories (CVE-2026-13676,
// CVE-2026-16221). Because no request is ever parsed by ajv, those advisories are inert.
// Removing this line, scoping it to a subset of routes, or adding a route that opts back
// into ajv validation (e.g. a raw JSON Schema `schema` on an instance without this
// compiler) silently reactivates host confusion inside an OAuth server. The
// `fast-uri: '>=3.1.8 <4'` floor in `pnpm-workspace.yaml` exists so this stops being the
// only mitigation, but do not rely on it alone.
// The second leg of the same invariant lives in the redirect_uri checks: matching is an
// exact string comparison (RFC 9700) with no URI parser in the security decision; the
// only relaxation, the port of a loopback redirect (RFC 8252 §7.3, #414), is lexical
// too — see `redirectUriMatchesRegistered` in `app/helpers/oauth-redirect.ts`. The
// schemas that feed it use `exactUrl` (`app/schemas/common.ts`), not `z.url()`, which
// since Zod 4.5 deletes tabs and line breaks from the value it returns.
//
// POSITION IS PART OF THE INVARIANT (#365). These two calls MUST run before
// `server.register(app)` below. A child scope snapshots the parent's validator and
// serializer compilers when it is created and Fastify does not propagate a later change
// into existing children, so moving these into `start()` — or anywhere after the app is
// registered — would silently return every autoloaded route to ajv validation, with no
// error and no warning. That is the same failure mode as #365 (a handler registered too
// late reaching nothing), here with a CVE behind it rather than an error shape.
server.setValidatorCompiler(validatorCompiler);
server.setSerializerCompiler(serializerCompiler);

async function shutdown(signal: string) {
  server.log.info(`${signal} received, shutting down gracefully...`);
  try {
    // close() also stops the job runner, which waits for a running job up to
    // its shutdown limit before the database pool closes (app/plugins/jobs.ts).
    await server.close();
    process.exit(0);
  } catch (error) {
    server.log.error(error, 'Error during shutdown');
    process.exit(1);
  }
}

// Handle shutdown signals
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Start server
async function start() {
  try {
    // Deprecated configuration names still work, but say so once at boot. The
    // env is parsed before the logger exists, so the warnings wait until here.
    for (const deprecation of envDeprecationWarnings) {
      server.log.warn(
        { variable: deprecation.variable, replacement: deprecation.replacement },
        deprecation.message
      );
    }
    // ADR-018 §5: an experimental key or value may change in any release, so
    // a deployment that sets one is told so at every boot. The switch of an
    // experimental feature warns through its feature instead, from `app.ts`
    // (`config/experimental-features.ts`).
    for (const experimental of envExperimentalWarnings) {
      server.log.warn({ variable: experimental.variable }, experimental.message);
    }

    // The database must have every migration of this release (#474, ADR-018
    // §5) before the boot steps read it. Behind, the server waits up to
    // DB_MIGRATION_WAIT_MS for the migration runner a deployment may start
    // beside it, then exits naming the missing migrations. Ahead, it starts:
    // during a rolling upgrade the old release runs on the new schema. Here,
    // before the app, because Fastify fails an `onReady` hook that runs
    // longer than its 10 s plugin timeout.
    await awaitDatabaseMigrations({
      connectionString: env.DATABASE_URL,
      waitMs: env.DB_MIGRATION_WAIT_MS,
      connectTimeoutMs: env.DB_POOL_CONNECTION_TIMEOUT,
      log: server.log,
    });

    // Swagger UI + OpenAPI spec registration. Gated behind `ENABLE_SWAGGER`
    // (F-07): defaults to `true` in non-production and `false` in production
    // so the API surface is not advertised to unauthenticated callers in a
    // hardened deployment. The spec is still registered (so routes are
    // discoverable for the Zod type provider) even when the UI is off — the
    // gate only suppresses the `/docs` route.
    await server.register(errorHandler);
    await server.register(swagger, openapiOptions);
    if (env.ENABLE_SWAGGER) {
      await server.register(swaggerUi, {
        routePrefix: '/docs',
        uiConfig: { docExpansion: 'list', filter: true },
      });
    }

    // Register app (routes) after swagger so they appear in OpenAPI spec
    await server.register(app);

    // Start listening.
    await server.listen({ port: env.PORT, host: env.HOST });
    server.log.info(`Server listening on http://${env.HOST}:${env.PORT}`);
  } catch (error) {
    server.log.error(error, 'Failed to start server');
    process.exit(1);
  }
}

start();
