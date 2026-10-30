import Fastify, { type FastifyInstance } from 'fastify';
import { serializerCompiler, validatorCompiler } from 'fastify-type-provider-zod';
import { afterEach, describe, expect, it } from 'vitest';

import {
  type AdminOperation,
  createOperationRegistry,
  defineOperation,
  operationSchemaExtensions,
} from '../helpers/admin-operations';
import { adminPipeline } from './pipeline';

/**
 * What the admin pipeline refuses at boot (#511): a route that names no realm
 * in its path, and a route with a hook of its own that would run before the
 * pipeline authorizes the caller. No database: nothing here takes a request.
 */

const READ = defineOperation({
  id: 'realms.get',
  class: 'read',
  effects: [],
  permissions: ['realms.read'],
  description: 'Read a realm (fixture).',
});
const REGISTRY = createOperationRegistry([READ] as AdminOperation[], { reserved: [] });

let instance: FastifyInstance | undefined;

afterEach(async () => {
  await instance?.close();
  instance = undefined;
});

/** Boot a bare listener with the pipeline in front of `route`. */
async function boot(route: (scope: FastifyInstance) => void): Promise<void> {
  const app = Fastify({ logger: false });
  instance = app;
  app.setValidatorCompiler(validatorCompiler);
  app.setSerializerCompiler(serializerCompiler);
  await app.register(adminPipeline, {
    registry: REGISTRY,
    bySubject: async () => undefined,
    routes: route,
  });
  await app.ready();
}

const options = { config: { operation: READ.id }, schema: operationSchemaExtensions(READ) };

describe('the admin pipeline at boot', () => {
  it('boots a route on the realm its path names', async () => {
    await expect(
      boot((scope) => {
        scope.get('/admin/v1-rc.0/realms/:realmId', options, async () => ({}));
      })
    ).resolves.toBeUndefined();
  });

  it('refuses a route that names no realm in its path', async () => {
    await expect(
      boot((scope) => {
        scope.get('/admin/v1-rc.0/realms', options, async () => ({}));
      })
    ).rejects.toThrow('every admin route acts on the realm its path names');
  });

  it.each(['onRequest', 'preParsing', 'preValidation'] as const)(
    'refuses a route with its own %s hook, which would run before authorization',
    async (hook) => {
      await expect(
        boot((scope) => {
          scope.get(
            '/admin/v1-rc.0/realms/:realmId',
            { ...options, [hook]: [async () => undefined] },
            async () => ({})
          );
        })
      ).rejects.toThrow(`has its own ${hook} hook`);
    }
  );

  it('boots a route with its own preHandler hook, which runs after the approval gate', async () => {
    await expect(
      boot((scope) => {
        scope.get(
          '/admin/v1-rc.0/realms/:realmId',
          { ...options, preHandler: [async () => undefined] },
          async () => ({})
        );
      })
    ).resolves.toBeUndefined();
  });
});
