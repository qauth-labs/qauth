import swagger from '@fastify/swagger';
import Fastify, { type FastifyInstance } from 'fastify';
import {
  serializerCompiler,
  validatorCompiler,
  type ZodTypeProvider,
} from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it } from 'vitest';
import { z } from 'zod';

import { checkApiConventions } from './api-conventions/openapi-conventions';
import { problemResponses } from './api-conventions/problem';
import {
  type AdminOperation,
  type Classification,
  createOperationRegistry,
  defineOperation,
  OPERATION_REGISTRY,
  type OperationClassification,
  type OperationRegistry,
  operationSchemaExtensions,
} from './helpers/admin-operations';
import { openapiOptions } from './openapi-options';
import { adminOperationsPlugin, requestClassification } from './plugins/admin-operations';

/**
 * THE ADMIN LISTENER REFUSES TO BOOT A ROUTE WITH NO REGISTERED OPERATION
 * (#508, ADR-019 Decision 7), on a real socket.
 *
 * The admin listener itself is #511's: a second Fastify instance for the
 * admin family, bound to its own host and port, with the pipeline in front of
 * every route. This suite builds that instance the way the pipeline will,
 * with the classification stage (`plugins/admin-operations.ts`), the Zod
 * compilers and the server's OpenAPI options, and listens on a loopback port:
 *
 * - with the server's own registry, which holds no operation yet, any admin
 *   route refuses the boot, and nothing listens;
 * - a route that names an unregistered operation, or whose schema disagrees
 *   with the registry, refuses it too;
 * - with a registry that holds the routes' operations, the listener boots,
 *   answers over HTTP with the classification each request needs, and the
 *   OpenAPI document it generates passes the API conventions check against
 *   the same registry.
 *
 * No container: the stage reads no database. The state a `classify`
 * compares with comes from the operation's `loadState`.
 */

const WRITE: Classification = {
  class: 'write',
  effects: [],
  permissions: ['realms.policies.write'],
};

const GET_OPERATION = defineOperation({
  id: 'realms.get',
  class: 'read',
  effects: [],
  permissions: ['realms.read'],
  description: 'Read a realm.',
});

/** A policy patch: write unless it lowers `minScore` below the current value. */
const PATCH_OPERATION = defineOperation<{ minScore: number }>({
  id: 'realms.policies.update',
  class: 'security',
  effects: ['credential-path', 'token-content', 'posture-loosening', 'administration'],
  permissions: ['realms.policies.write', 'realms.policies.security'],
  description: "Change a realm's policies.",
  loadState: async () => ({ minScore: 2 }),
  stateVersion: () => '1',
  classify: (request, current) => {
    const body = request.body as { minScore?: number };
    return body.minScore !== undefined && body.minScore < current.minScore
      ? {
          class: 'security',
          effects: ['credential-path'],
          permissions: ['realms.policies.security'],
        }
      : WRITE;
  },
});

// The fixture's classify knows only `minScore`, not the reserved table's
// policy cases (`vectors`), so the fixture is checked without the table.
const FIXTURE_REGISTRY = createOperationRegistry(
  [GET_OPERATION, PATCH_OPERATION] as AdminOperation[],
  { reserved: [] }
);

const realmParams = z.object({ realmId: z.uuid() });
const REALM_ID = '018f2d6e-8a8b-7c3d-9e0f-1a2b3c4d5e6f';

let listener: FastifyInstance | undefined;

afterEach(async () => {
  await listener?.close();
  listener = undefined;
});

/** An admin listener with the stage in front of `routes`, listening on loopback. */
async function startAdminListener(
  registry: OperationRegistry,
  routes: (instance: FastifyInstance) => void
): Promise<string> {
  const app = Fastify({ logger: false }).withTypeProvider<ZodTypeProvider>();
  listener = app;
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  // A PATCH body is a JSON Merge Patch (API conventions).
  app.addContentTypeParser(
    'application/merge-patch+json',
    { parseAs: 'string' },
    app.getDefaultJsonParser('error', 'error')
  );
  await app.register(swagger, openapiOptions);
  await app.register(adminOperationsPlugin, {
    registry,
    // The listener's authorization stage (#511) checks the caller's
    // permissions; this suite exercises the classification only.
    authorize: () => undefined,
  });
  await app.register(async (scope) => routes(scope));
  return app.listen({ host: '127.0.0.1', port: 0 });
}

/** The two reference routes, each answering with the classification it received. */
function referenceRoutes(instance: FastifyInstance): void {
  const typed = instance.withTypeProvider<ZodTypeProvider>();
  typed.get(
    '/admin/v1-rc.0/realms/:realmId',
    {
      config: { operation: 'realms.get' },
      schema: {
        ...operationSchemaExtensions(GET_OPERATION),
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'experimental',
        params: realmParams,
        response: { 200: z.object({ class: z.string() }), ...problemResponses(401, 403, 404) },
      },
    },
    async (request) => ({ class: requestClassification(request).class })
  );
  typed.patch(
    '/admin/v1-rc.0/realms/:realmId/policies',
    {
      config: { operation: 'realms.policies.update' },
      schema: {
        ...operationSchemaExtensions(PATCH_OPERATION as AdminOperation),
        security: [{ bearerAuth: [] }],
        'x-qauth-stability': 'experimental',
        consumes: ['application/merge-patch+json'],
        params: realmParams,
        headers: z.looseObject({ 'if-match': z.string() }),
        body: z.strictObject({ minScore: z.int().min(0).max(4).optional() }),
        response: {
          200: z.object({ class: z.string(), permissions: z.array(z.string()) }),
          ...problemResponses(400, 401, 403, 404, 412, 422, 428),
        },
      },
    },
    async (request) => {
      const classification: OperationClassification = requestClassification(request);
      return { class: classification.class, permissions: [...classification.permissions] };
    }
  );
}

describe('the admin listener boot check (#508)', () => {
  // Acceptance criterion: the admin listener refuses to boot when a route has
  // no registered operation.
  it('refuses to boot a route that names no operation, and listens on nothing', async () => {
    await expect(
      startAdminListener(OPERATION_REGISTRY, (scope) =>
        scope.get('/admin/v1-rc.0/realms/:realmId', async () => ({}))
      )
    ).rejects.toThrow(/GET \/admin\/v1-rc.0\/realms\/:realmId has no admin operation/);
    expect(listener?.server.listening).toBe(false);
  });

  it('refuses to boot a route whose operation the server registry does not hold yet', async () => {
    await expect(startAdminListener(OPERATION_REGISTRY, referenceRoutes)).rejects.toThrow(
      /names the admin operation "realms.get", which the operation registry does not hold/
    );
    expect(listener?.server.listening).toBe(false);
  });

  it('refuses to boot a route whose schema disagrees with the registry', async () => {
    await expect(
      startAdminListener(FIXTURE_REGISTRY, (scope) =>
        scope.get(
          '/admin/v1-rc.0/realms/:realmId',
          {
            config: { operation: 'realms.get' },
            schema: { ...operationSchemaExtensions(GET_OPERATION), 'x-qauth-class': 'write' },
          },
          async () => ({})
        )
      )
    ).rejects.toThrow(/x-qauth-class is "write", but the registry's realms.get gives "read"/);
    expect(listener?.server.listening).toBe(false);
  });

  it('boots registered routes, classifies each request over HTTP, and publishes what the registry says', async () => {
    const address = await startAdminListener(FIXTURE_REGISTRY, referenceRoutes);
    expect(listener?.server.listening).toBe(true);

    const read = await fetch(`${address}/admin/v1-rc.0/realms/${REALM_ID}`);
    expect(read.status).toBe(200);
    expect(await read.json()).toEqual({ class: 'read' });

    const patch = (body: unknown) =>
      fetch(`${address}/admin/v1-rc.0/realms/${REALM_ID}/policies`, {
        method: 'PATCH',
        headers: { 'content-type': 'application/merge-patch+json', 'if-match': '"1"' },
        body: JSON.stringify(body),
      });
    const raise = await patch({ minScore: 3 });
    expect(await raise.json()).toEqual({ class: 'write', permissions: ['realms.policies.write'] });
    const lower = await patch({ minScore: 1 });
    expect(await lower.json()).toEqual({
      class: 'security',
      permissions: ['realms.policies.security'],
    });

    // The document the booted listener generates is the registry's.
    const document = structuredClone(listener?.swagger());
    const report = checkApiConventions(document, { operations: FIXTURE_REGISTRY });
    expect(report.checkedOperations).toBe(2);
    expect(report.violations).toEqual([]);
    expect(
      (document as unknown as { paths: Record<string, Record<string, Record<string, unknown>>> })
        .paths['/admin/v1-rc.0/realms/{realmId}/policies'].patch
    ).toMatchObject({
      operationId: 'realms.policies.update',
      'x-qauth-class': 'security',
      'x-qauth-permission': ['realms.policies.write', 'realms.policies.security'],
      'x-qauth-effects': [
        'credential-path',
        'token-content',
        'posture-loosening',
        'administration',
      ],
      'x-qauth-two-admin': 'recommended',
    });
  });
});
