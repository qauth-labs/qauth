/// <reference types="vitest/globals" />
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';
import {
  isResponseSerializationError,
  serializerCompiler,
  validatorCompiler,
  ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { z } from 'zod';

import { openapiOptions } from './openapi-options';
import {
  introspectRequestSchema,
  introspectResponseSchema,
  userinfoResponseSchema,
} from './schemas/oauth';

/**
 * Verifies that OpenAPI spec and Swagger UI are configured and that Phase 1.7
 * endpoints (GET /oauth/userinfo, POST /oauth/introspect) appear in the spec.
 * Does not start the full app (no DB/Redis); only swagger + minimal route schemas.
 */
describe('OpenAPI / Swagger', () => {
  it('exposes Phase 1.7 endpoints in the OpenAPI spec', async () => {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);

    // Shared with `main.ts` (the running server) and `openapi-export.ts` (the
    // offline exporter) via `openapi-options.ts`, rather than a third
    // independent copy here — this file used to carry its own inline `info`/
    // `components` block, which is exactly the kind of copy that drifted
    // stale (qauth-labs/qauth#351 fix round 1).
    await app.register(swagger, openapiOptions);

    await app.register(swaggerUi, {
      routePrefix: '/docs',
      uiConfig: { docExpansion: 'list', filter: true },
    });

    // Register routes with same schema as real Phase 1.7 routes so spec is generated
    app.withTypeProvider<ZodTypeProvider>().get(
      '/oauth/userinfo',
      {
        schema: {
          description:
            'OIDC userinfo endpoint. Returns claims for the authenticated user. Requires Bearer access token.',
          tags: ['OAuth', 'Userinfo'],
          security: [{ bearerAuth: [] }],
          response: { 200: userinfoResponseSchema },
        },
      },
      async () => ({ sub: 'test', email: 'test@example.com', email_verified: true })
    );

    app.withTypeProvider<ZodTypeProvider>().post(
      '/oauth/introspect',
      {
        schema: {
          description:
            'RFC 7662 token introspection. Send access token and client credentials in application/x-www-form-urlencoded body.',
          tags: ['OAuth', 'Introspection'],
          body: introspectRequestSchema,
          response: { 200: introspectResponseSchema },
        },
      },
      async () => ({ active: false })
    );

    await app.ready();

    const spec = app.swagger() as {
      openapi?: string;
      info?: { title?: string };
      components?: unknown;
      paths?: Record<string, unknown>;
    };
    expect(spec.openapi).toBe('3.1.0');
    expect(spec.info?.title).toBe('QAuth Auth Server API');
    expect(spec.components).toBeDefined();
    expect(spec.paths?.['/oauth/userinfo']).toBeDefined();
    expect((spec.paths?.['/oauth/userinfo'] as { get?: unknown })?.get).toBeDefined();
    expect(spec.paths?.['/oauth/introspect']).toBeDefined();
    expect((spec.paths?.['/oauth/introspect'] as { post?: unknown })?.post).toBeDefined();

    const docsResponse = await app.inject({ method: 'GET', url: '/docs' });
    expect(docsResponse.statusCode).toBe(200);
    expect(docsResponse.headers['content-type']).toMatch(/text\/html/);

    await app.close();
  });

  it('serves the swagger-ui static assets (#323)', async () => {
    // Only swagger + swagger-ui are needed here — no route schemas, since this
    // exercises the asset pipeline rather than the spec.
    const app = Fastify({ logger: false });
    await app.register(swagger, {
      openapi: { openapi: '3.1.0', info: { title: 't', version: '1' } },
    });
    await app.register(swaggerUi, { routePrefix: '/docs' });
    await app.ready();

    // The assertion above only reaches swagger-ui's own HTML handler. The
    // bundled assets are what actually goes through @fastify/static, which is
    // pinned to ^10.1.2 by a pnpm-workspace.yaml override — swagger-ui itself
    // still declares ^9.1.2, and the 9.x line has no fix for CVE-2026-15074.
    // Nothing else in the repo exercises that plugin, so without this a broken
    // major would surface as a 404 on /docs assets in a browser, not in CI.
    const css = await app.inject({ method: 'GET', url: '/docs/static/index.css' });
    expect(css.statusCode).toBe(200);

    // v10.1.1 fixed a route-guard bypass by returning 403 on dot-dot segments
    // rather than letting them fall through. Either a rejection or a plain
    // not-found is acceptable; escaping the asset root is not.
    const traversal = await app.inject({
      method: 'GET',
      url: '/docs/static/../../oauth/userinfo',
    });
    expect(traversal.statusCode).not.toBe(200);

    await app.close();
  });

  // ── fastify-type-provider-zod v7: responses serialize in the ENCODE direction
  //
  // v6's serializerCompiler ran `safeParse` over the outgoing payload, so a
  // response schema could carry decode-side machinery — `.transform()`,
  // `.pipe()`, `.default()` — and it would quietly run on the way OUT. v7
  // switched to `safeEncode`, which walks the schema backwards: a unidirectional
  // transform now throws, and `.default()` no longer fills a missing key.
  //
  // Every response schema in this repo was audited at bump time and none uses
  // such a construct (the `.transform()` / `z.coerce` uses are all in REQUEST
  // schemas, and `validatorCompiler` still uses `safeParse`, so the request path
  // is untouched). The two tests below pin that contract down, because the
  // failure mode is a runtime 500 on a single endpoint — invisible to a spec
  // presence check like the one above, and invisible to typechecking.
  it('serializes a plain response schema in the encode direction (v7)', async () => {
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setValidatorCompiler(validatorCompiler);
    app.setSerializerCompiler(serializerCompiler);
    app.get('/encode-ok', { schema: { response: { 200: userinfoResponseSchema } } }, async () => ({
      sub: 'user-1',
      email: 'user@example.com',
      email_verified: true,
    }));
    await app.ready();

    const res = await app.inject({ method: 'GET', url: '/encode-ok' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ sub: 'user-1', email_verified: true });

    await app.close();
  });

  it('rejects encode-hostile response schemas (v7)', async () => {
    // Guard, not a behaviour we want: adding `.transform()` or `.default()` to
    // a *response* schema must fail loudly rather than silently shipping a
    // mangled body. Under v6 both of these produced a 200 with a rewritten
    // payload (`{"n":"1"}` / `{"items":[]}`), which is exactly the kind of
    // silent change this asserts against. If these ever start returning 200,
    // the serializer has gone back to the decode direction and the response
    // schemas need re-auditing.
    const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
    app.setSerializerCompiler(serializerCompiler);

    const captured: Record<string, unknown> = {};
    app.setErrorHandler((error, request, reply) => {
      captured[request.url] = error;
      return reply.status(500).send({ error: 'serialization' });
    });
    app.get(
      '/one-way-transform',
      { schema: { response: { 200: z.object({ n: z.number().transform(String) }) } } },
      async () => ({ n: 1 }) as never
    );
    app.get(
      '/response-default',
      { schema: { response: { 200: z.object({ items: z.array(z.string()).default([]) }) } } },
      async () => ({}) as never
    );
    await app.ready();

    // A unidirectional transform is caught inside Zod itself, so it surfaces as
    // a raw `$ZodEncodeError` rather than the provider's wrapper type.
    const transformRes = await app.inject({ method: 'GET', url: '/one-way-transform' });
    expect(transformRes.statusCode).toBe(500);
    expect(String((captured['/one-way-transform'] as Error).message)).toMatch(
      /unidirectional transform/i
    );

    // A missing key with a `.default()` fails the encode as an ordinary schema
    // mismatch, which the provider does wrap.
    const defaultRes = await app.inject({ method: 'GET', url: '/response-default' });
    expect(defaultRes.statusCode).toBe(500);
    expect(isResponseSerializationError(captured['/response-default'])).toBe(true);

    await app.close();
  });
});
