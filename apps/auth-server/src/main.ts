import { randomUUID } from 'node:crypto';

import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify, { LogController } from 'fastify';
import { serializerCompiler, validatorCompiler, ZodTypeProvider } from 'fastify-type-provider-zod';

import { app } from './app/app';
import { openapiOptions } from './app/openapi-options';
import { env } from './config/env';
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
  routerOptions: {
    ignoreTrailingSlash: true,
  },
}).withTypeProvider<ZodTypeProvider>();

// Set up Zod validator and serializer.
//
// SECURITY INVARIANT — this global Zod validator compiler is load-bearing beyond typing.
// It replaces Fastify's default `ajv` compiler for *every* route, and `ajv` is what pulls
// `fast-uri`, which carries two unfixed-in-tree host-confusion advisories (CVE-2026-13676,
// CVE-2026-16221). Because no request is ever parsed by ajv, those advisories are inert.
// Removing this line, scoping it to a subset of routes, or adding a route that opts back
// into ajv validation (e.g. a raw JSON Schema `schema` on an instance without this
// compiler) silently reactivates host confusion inside an OAuth server. The
// `fast-uri: '>=3.1.4 <4'` floor in `pnpm-workspace.yaml` exists so this stops being the
// only mitigation, but do not rely on it alone.
// The second leg of the same invariant lives in the redirect_uri checks: matching is an
// exact string comparison (`client.redirectUris.includes(...)`, RFC 9700) with no URI
// parser in the security decision — see `app/helpers/oauth-redirect.ts`.
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
    // Swagger UI + OpenAPI spec registration. Gated behind `ENABLE_SWAGGER`
    // (F-07): defaults to `true` in non-production and `false` in production
    // so the API surface is not advertised to unauthenticated callers in a
    // hardened deployment. The spec is still registered (so routes are
    // discoverable for the Zod type provider) even when the UI is off — the
    // gate only suppresses the `/docs` route.
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
