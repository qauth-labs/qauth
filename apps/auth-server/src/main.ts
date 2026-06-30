import { randomUUID } from 'node:crypto';

import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';
import {
  createJsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
  ZodTypeProvider,
} from 'fastify-type-provider-zod';

import { app } from './app/app';
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
//   (#128).
const server = Fastify({
  logger: buildLoggerOptions(env),
  requestIdHeader: env.REQUEST_ID_HEADER,
  requestIdLogLabel: 'reqId',
  genReqId: () => randomUUID(),
  routerOptions: {
    ignoreTrailingSlash: true,
  },
}).withTypeProvider<ZodTypeProvider>();

// Set up Zod validator and serializer
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
    await server.register(swagger, {
      openapi: {
        openapi: '3.1.0',
        info: {
          title: 'QAuth Auth Server API',
          description:
            'OAuth 2.1 / OIDC authentication server API. Phase 1.7: userinfo and token introspection.',
          version: '1.0.0',
        },
        servers: [{ url: '/', description: 'Default' }],
        components: {
          securitySchemes: {
            bearerAuth: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT',
              description: 'Access token obtained from login, refresh, or OAuth token endpoint.',
            },
          },
        },
      },
      transform: createJsonSchemaTransform({
        zodToJsonConfig: { target: 'draft-2020-12' },
      }),
    });
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
