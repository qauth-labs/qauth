import type * as SwaggerPlugin from '@fastify/swagger';
import { createJsonSchemaTransform } from 'fastify-type-provider-zod';

/**
 * `@fastify/swagger` registration options — the `openapi` object plus the
 * `transform` — shared verbatim by `main.ts` (the running server, `/docs`)
 * and `openapi-export.ts` (the offline exporter that writes
 * `apps/docs-site/public/openapi.json`, #347). Before this extraction (#347
 * fix round 3) both files carried an independent copy of this object, and
 * Task 3's endpoint-coverage guard compares PATHS only, so it would never
 * have caught the two copies' `info`/`components` metadata drifting apart —
 * one file feeding the published docs site, the other feeding the live
 * Swagger UI. A single shared constant removes that whole class of drift
 * instead of relying on a guard to notice it.
 *
 * PURE EXTRACTION: identical bytes to what both files carried before. In
 * particular, `info.description`'s "Phase 1.7: userinfo and token
 * introspection" wording is known-stale and is deliberately left as-is here —
 * correcting it is a later content task's call, not this one's.
 *
 * (`apps/auth-server/src/app/openapi.test.ts` carries its own separate copy
 * of this same object, for a minimal Fastify instance rather than the real
 * app — left alone; whether that test should import this constant too is a
 * judgement call for the reviewer, not something folded into this
 * extraction.)
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
};
