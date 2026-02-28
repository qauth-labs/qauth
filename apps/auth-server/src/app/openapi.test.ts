/// <reference types="vitest/globals" />
import swagger from '@fastify/swagger';
import swaggerUi from '@fastify/swagger-ui';
import Fastify from 'fastify';
import {
  createJsonSchemaTransform,
  serializerCompiler,
  validatorCompiler,
  ZodTypeProvider,
} from 'fastify-type-provider-zod';

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

    await app.register(swagger, {
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
});
