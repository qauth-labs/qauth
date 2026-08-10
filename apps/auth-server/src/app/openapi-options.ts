import type * as SwaggerPlugin from '@fastify/swagger';
import { createJsonSchemaTransform } from 'fastify-type-provider-zod';

/**
 * `@fastify/swagger` registration options — the `openapi` object plus the
 * `transform` — shared verbatim by `main.ts` (the running server, `/docs`),
 * `openapi-export.ts` (the offline exporter that writes
 * `apps/docs-site/public/openapi.json`, #347) and `openapi.test.ts` (which
 * registers it on a minimal Fastify instance rather than the real app).
 * Before this extraction (#347 fix round 3) the first two each carried an
 * independent copy of this object, and Task 3's endpoint-coverage guard
 * compares PATHS only, so it would never have caught the two copies'
 * `info`/`components` metadata drifting apart — one file feeding the
 * published docs site, the other feeding the live Swagger UI. A single shared
 * constant removes that whole class of drift instead of relying on a guard to
 * notice it.
 *
 * PURE EXTRACTION at the time this file was created: identical bytes to what
 * those two carried before. `info.description`'s original "Phase 1.7:
 * userinfo and token introspection" wording was known-stale and was
 * deliberately left as-is by that extraction, pending a later content task
 * (#351) to own the correction — that task has since updated it below.
 *
 * Explicitly typed as `SwaggerPlugin.FastifyDynamicSwaggerOptions` — without
 * this, TS infers `type: 'http'` (a required literal on `HttpSecurityScheme`)
 * as the widened `string`, because a standalone object literal has no
 * contextual type to narrow against the way it did when it was written
 * inline as `server.register(swagger, { ... })`'s second argument in each
 * call site. Needed for the extraction to compile as-is; the VALUES below
 * are unchanged.
 */
export const openapiOptions: SwaggerPlugin.FastifyDynamicSwaggerOptions = {
  openapi: {
    openapi: '3.1.0',
    info: {
      title: 'QAuth Auth Server API',
      description:
        'OAuth 2.1 / OIDC 1.0 authorization server for MCP servers and AI agents: authorization_code + PKCE and client_credentials grants, RFC 8693 on-behalf-of agent delegation, and environment-aware authorization policy. Wallet federation (OID4VP) transport ships behind a default-off flag.',
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
};
