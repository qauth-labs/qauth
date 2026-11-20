import { describe, expect, it } from 'vitest';

import { OPERATION_REGISTRY } from '../../helpers/admin-operations';
import { PERMISSION_REGISTRY } from '../../helpers/admin-permissions';
import { BUILT_IN_ROLES } from '../../helpers/admin-roles';
import { scopesOf } from '../change-preview';
import type { AdminRateLimitCheck } from '../pipeline';
import { EXPORT_OPERATION_IDS } from './operations';

/**
 * The export operation (#530): a read that needs realms.export, which every
 * built-in role holds, so a token with qauth:admin:read alone exports; and
 * its route passes the API conventions.
 */

describe('the export operation (#530)', () => {
  it('is a read that needs realms.export, under qauth:admin:read', () => {
    const operation = OPERATION_REGISTRY.get(EXPORT_OPERATION_IDS.export);
    expect(operation).toMatchObject({ class: 'read', effects: [], permissions: ['realms.export'] });
    expect(PERMISSION_REGISTRY.get('realms.export')?.class).toBe('read');
    expect(scopesOf(operation?.permissions ?? [], PERMISSION_REGISTRY)).toEqual([
      'qauth:admin:read',
    ]);
  });

  it('is open to every built-in role that reads, the viewer included', () => {
    for (const role of Object.values(BUILT_IN_ROLES)) {
      if (!role.classes.includes('read')) continue;
      expect(role.permissionIds, role.name).toContain('realms.export');
    }
    expect(BUILT_IN_ROLES.viewer.permissionIds).toContain('realms.export');
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
    const { exportRoutes } = await import('./routes');

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
          await scope.register(exportRoutes);
        },
      });
      await app.ready();

      const document = app.swagger() as unknown as {
        paths: Record<string, Record<string, Record<string, unknown>>>;
      };
      expect(Object.keys(document.paths)).toEqual(['/admin/v1-rc.0/realms/{realmId}/realm-file']);
      const get = document.paths['/admin/v1-rc.0/realms/{realmId}/realm-file']['get'];
      expect(get).toMatchObject({
        operationId: EXPORT_OPERATION_IDS.export,
        'x-qauth-class': 'read',
        'x-qauth-permission': 'realms.export',
        'x-qauth-stability': 'experimental',
      });
      expect(JSON.stringify(get['responses'])).toContain('AdminRealmFile');
      const report = checkApiConventions(document, { operations: OPERATION_REGISTRY });
      expect(report.violations).toEqual([]);
      expect(report.checkedOperations).toBe(1);
    } finally {
      await app.close();
    }
  });
});
