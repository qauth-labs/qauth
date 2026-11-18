import { REALM_FILE_SECTIONS } from '@qauth-labs/realm-file';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';

import { OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { PERMISSION_REGISTRY } from '../../helpers/admin-permissions';
import { scopesOf } from '../change-preview';
import type { AdminRateLimitCheck } from '../pipeline';
import { IMPORT_OPERATION_IDS } from './operations';
import { IMPORT_SECTIONS } from './plan';
import { defineSection } from './section';

/**
 * The import's section registry and its operation (#518): the two sections
 * follow the realm file's format, the dry run is a read that needs
 * realms.import.plan, and its route passes the API conventions.
 */

describe('the section registry (#518)', () => {
  it('ships policies and clients, keyed as the realm file keys them', () => {
    expect(IMPORT_SECTIONS.map(({ name, naturalKey }) => ({ name, naturalKey }))).toEqual([
      { name: 'policies', naturalKey: undefined },
      { name: 'clients', naturalKey: 'client_id' },
    ]);
    const order = REALM_FILE_SECTIONS.map((section) => section.name);
    const positions = IMPORT_SECTIONS.map((section) => order.indexOf(section.name));
    expect(positions).toEqual([...positions].sort((a, b) => a - b));
  });

  it('refuses a section the realm file does not have, or keyed otherwise', () => {
    const base = {
      schema: () => z.object({}),
      diff: () => ({ changes: [] }),
      permissionsFor: () => [],
    };
    expect(() => defineSection({ ...base, name: 'webhooks', naturalKey: 'url' })).toThrow(
      'webhooks is not a section of the realm file'
    );
    expect(() => defineSection({ ...base, name: 'clients', naturalKey: 'name' })).toThrow(
      'The realm file matches clients by client_id, not name'
    );
  });

  it('names only permissions the catalog holds', () => {
    for (const permission of [
      'clients.write',
      'clients.security',
      'realms.policies.write',
      'realms.policies.security',
      'realms.import.plan',
    ]) {
      expect(PERMISSION_REGISTRY.get(permission), permission).toBeDefined();
    }
    expect(PERMISSION_REGISTRY.get('clients.write')?.class).toBe('write');
    expect(PERMISSION_REGISTRY.get('clients.security')?.class).toBe('security');
  });
});

describe('the dry-run operation (#518)', () => {
  it('is a read that needs realms.import.plan and the reads of what it shows', () => {
    expect(OPERATION_REGISTRY.get(IMPORT_OPERATION_IDS.plan)).toMatchObject({
      class: 'read',
      effects: [],
      permissions: ['realms.import.plan', 'realms.read', 'clients.read'],
    });
    expect(
      scopesOf(
        OPERATION_REGISTRY.get(IMPORT_OPERATION_IDS.plan)?.permissions ?? [],
        PERMISSION_REGISTRY
      )
    ).toEqual(['qauth:admin:read']);
  });

  it('passes the API conventions in the admin OpenAPI document', async () => {
    const [{ default: Fastify }, { default: swagger }, zod, { adminOpenapiOptions }, pipeline] =
      await Promise.all([
        import('fastify'),
        import('@fastify/swagger'),
        import('fastify-type-provider-zod'),
        import('../openapi-options'),
        import('../pipeline'),
      ]);
    const { checkApiConventions } = await import('../../api-conventions/openapi-conventions');
    const { importRoutes } = await import('./routes');

    const app = Fastify({ logger: false });
    try {
      app.setValidatorCompiler(zod.validatorCompiler);
      app.setSerializerCompiler(zod.serializerCompiler);
      await app.register(swagger, adminOpenapiOptions);
      const uncounted: AdminRateLimitCheck = async () => ({ isAllowed: true, key: 'uncounted' });
      await app.register(pipeline.adminPipeline, {
        registry: OPERATION_REGISTRY,
        refusalsByAddress: uncounted,
        callsBySubject: uncounted,
        routes: async (scope) => {
          await scope.register(importRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as unknown as {
        paths: Record<string, Record<string, Record<string, unknown>>>;
      };
      expect(Object.keys(document.paths)).toEqual(['/admin/v1-rc.0/realms/{realmId}/imports']);
      const post = document.paths['/admin/v1-rc.0/realms/{realmId}/imports']['post'];
      expect(post).toMatchObject({
        operationId: IMPORT_OPERATION_IDS.plan,
        'x-qauth-class': 'read',
        'x-qauth-stability': 'experimental',
      });
      expect(JSON.stringify(post['requestBody'])).toContain('AdminRealmImportRequest');
      expect(JSON.stringify(post['responses'])).toContain('AdminImportPlan');
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(1);
    } finally {
      await app.close();
    }
  });
});
