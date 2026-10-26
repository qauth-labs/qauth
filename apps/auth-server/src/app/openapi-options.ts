import type * as SwaggerPlugin from '@fastify/swagger';
import {
  createJsonSchemaTransform,
  createJsonSchemaTransformObject,
} from 'fastify-type-provider-zod';

import { OAUTH_ERROR_MEDIA_TYPE, OAUTH_ERROR_SCHEMA_REF } from './api-conventions/oauth-error';
import { PROBLEM_MEDIA_TYPE, PROBLEM_SCHEMA_REF, statusTitle } from './api-conventions/problem';

/**
 * Where one HTTP operation stands under the ADR-018 §5 stability contract.
 * `experimental` operations sit behind a switch and may change in a minor
 * release; everything else is `stable`.
 */
export type OperationStability = 'stable' | 'experimental';

/**
 * What an admin, account or developer API operation does, for authorization
 * (ADR-019 Decision 7, #506). On the admin API the class names the scope it
 * needs: `admin:read`, `admin:write` or `admin:security`. `security` is used on
 * the admin API only.
 */
export type OperationClass = 'read' | 'write' | 'security';

declare module 'fastify' {
  interface FastifySchema {
    /**
     * Required on every route schema, though optional in the type so that
     * routes outside this app are not forced to carry it. `@fastify/swagger`
     * copies every `x-` key of a route schema onto the OpenAPI operation, where
     * the stable-surface check (`scripts/stable-surface/`) fails CI when an
     * operation lacks it and skips `experimental` operations in its break
     * check.
     */
    'x-qauth-stability'?: OperationStability;
    /**
     * The extensions below are required on every operation of the admin,
     * account and developer APIs and absent elsewhere. The API conventions
     * check (`api-conventions/openapi-conventions.ts`) enforces them over the
     * generated document; the docs site's `reference/api-conventions.md`
     * defines them.
     */
    'x-qauth-class'?: OperationClass;
    /** The permission the caller needs, or the list when the request decides which. */
    'x-qauth-permission'?: string | readonly string[];
    /** The effects that make an admin operation a security operation (ADR-019 Decision 7). */
    'x-qauth-effects'?: readonly string[];
    /** Set on every admin security operation: the console recommends a second admin. */
    'x-qauth-two-admin'?: 'recommended';
    /**
     * The error statuses the operation answers by design (#513), such as
     * `[400, 401, 404]`. The OpenAPI document lists each one, and 421, 429 and
     * 500, which any operation of a realm may answer, as a response carrying
     * the route's error format: the shared `Problem` schema, or `OAuthError` on
     * an OAuth protocol endpoint. A status the route's `response` already
     * declares keeps that declaration. Documentation only: the key changes
     * nothing at run time.
     */
    'x-qauth-errors'?: readonly number[];
  }
}

/** The extension keys the per-route transform leaves for the document transform. */
const ERROR_STATUSES_KEY = 'x-qauth-error-statuses';
const ERROR_FORMAT_KEY = 'x-qauth-error-format';

/**
 * The error statuses one operation's document lists (#513): the ones it
 * declares, 429 unless the route has `rateLimit: false`, and 421 and 500,
 * which every operation of a realm may answer (the realm resolver and an
 * unexpected failure). A `none` route such as `/health` belongs to no realm
 * and answers its own failures, so it adds only the 429.
 */
function documentedErrorStatuses(
  declared: readonly number[] | undefined,
  config: { surface?: string; rateLimit?: unknown } | undefined
): number[] {
  const statuses = new Set(declared ?? []);
  if (config?.rateLimit !== false) statuses.add(429);
  if (config?.surface !== 'none') {
    statuses.add(421);
    statuses.add(500);
  }
  return [...statuses].sort((a, b) => a - b);
}

/** The HTTP methods an OpenAPI path item holds operations under. */
const OPERATION_METHODS = ['get', 'put', 'post', 'delete', 'options', 'head', 'patch', 'trace'];

/**
 * Add each operation's error responses (#513), from what
 * {@link transformRoute} left on it: one entry per status, `application/json`
 * with a `$ref` to `OAuthError` on an OAuth protocol endpoint, else
 * `application/problem+json` with a `$ref` to `Problem`. A status the
 * operation already declares is left as declared. The two extension keys are
 * removed.
 */
function withErrorResponses<Document extends { paths?: unknown }>(document: Document): Document {
  const paths = (document.paths ?? {}) as Record<string, Record<string, unknown>>;
  for (const pathItem of Object.values(paths)) {
    for (const method of OPERATION_METHODS) {
      const operation = pathItem[method] as Record<string, unknown> | undefined;
      if (operation === undefined) continue;
      const statuses = (operation[ERROR_STATUSES_KEY] as number[] | undefined) ?? [];
      const oauth = operation[ERROR_FORMAT_KEY] === 'oauth';
      delete operation[ERROR_STATUSES_KEY];
      delete operation[ERROR_FORMAT_KEY];
      const responses = (operation['responses'] ?? {}) as Record<string, unknown>;
      for (const status of statuses) {
        if (Object.hasOwn(responses, String(status))) continue;
        responses[String(status)] = {
          description: statusTitle(status),
          content: oauth
            ? { [OAUTH_ERROR_MEDIA_TYPE]: { schema: { $ref: OAUTH_ERROR_SCHEMA_REF } } }
            : { [PROBLEM_MEDIA_TYPE]: { schema: { $ref: PROBLEM_SCHEMA_REF } } },
        };
      }
      operation['responses'] = responses;
    }
  }
  return document;
}

/** Where `@fastify/swagger` and the Zod transform put named schemas. */
const COMPONENT_SCHEMA_REF = '#/components/schemas/';

/**
 * Keep only the component schemas the document's operations reference,
 * directly or through another component.
 *
 * The Zod transform below turns a schema registered with an `id` (the shared
 * `Problem` schema, `api-conventions/problem.ts`) into a `$ref`, and
 * `createJsonSchemaTransformObject` adds every registered schema to
 * `components.schemas`, used or not, each twice: as an output schema and as an
 * `…Input` copy. A document then lists `ProblemInput`, which no operation
 * accepts, and `Problem` on a surface with no operation that answers it. Only
 * what a reference reaches is published.
 */
function withReferencedSchemasOnly<
  Document extends { paths?: unknown; components?: { schemas?: Record<string, unknown> } },
>(document: Document): Document {
  const schemas: Record<string, unknown> = { ...document.components?.schemas };
  const referenced = new Set<string>();

  const visit = (node: unknown): void => {
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (node === null || typeof node !== 'object') return;
    for (const [key, value] of Object.entries(node)) {
      if (key === '$ref' && typeof value === 'string' && value.startsWith(COMPONENT_SCHEMA_REF)) {
        const name = value.slice(COMPONENT_SCHEMA_REF.length);
        if (!referenced.has(name)) {
          referenced.add(name);
          visit(schemas[name]);
        }
      } else {
        visit(value);
      }
    }
  };
  visit(document.paths);

  return {
    ...document,
    components: {
      ...document.components,
      schemas: Object.fromEntries(Object.entries(schemas).filter(([name]) => referenced.has(name))),
    },
  };
}

const zodToJsonConfig = { target: 'draft-2020-12' } as const;

const addComponentSchemas = createJsonSchemaTransformObject({ zodToJsonConfig });

/**
 * The per-route transform: Zod to JSON Schema, then the route's error statuses
 * and error format left on the operation for {@link withErrorResponses}, which
 * cannot see the route.
 */
const zodTransform = createJsonSchemaTransform({ zodToJsonConfig });

const transformRoute: SwaggerPlugin.SwaggerTransform = (input) => {
  const { schema, url } = zodTransform(input);
  const { 'x-qauth-errors': declared, ...rest } = schema as typeof schema & {
    'x-qauth-errors'?: readonly number[];
  };
  const config = input.route.config as
    | { surface?: string; rateLimit?: unknown; errorFormat?: string }
    | undefined;
  return {
    url,
    schema: {
      ...rest,
      [ERROR_STATUSES_KEY]: documentedErrorStatuses(declared, config),
      [ERROR_FORMAT_KEY]: config?.errorFormat === 'oauth' ? 'oauth' : 'problem',
    },
  };
};

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
  transform: transformRoute,
  transformObject: (documentObject) =>
    withReferencedSchemasOnly(withErrorResponses(addComponentSchemas(documentObject))),
};
