import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  createPermissionRegistry,
  definePermission,
  PERMISSION_REGISTRY,
} from './admin-permissions';
import {
  ADMIN_PERMISSIONS_SURFACE_PATH,
  adminPermissionsSurfaceText,
  renderAdminPermissionsSurface,
} from './admin-permissions-surface';

/**
 * The admin permission catalog's stable surface (#507). The stable-surface
 * check compares the committed file with the latest release, so a removed
 * permission or a changed class is reported even when the docs page has been
 * regenerated twice; this test keeps the file in step with the registry and
 * registered with the check.
 */

const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');

interface CatalogSchema {
  required: string[];
  properties: Record<
    string,
    {
      required: string[];
      properties: { class: { enum: string[] }; retiredIn?: { enum: string[] } };
    }
  >;
}

describe('the admin permission catalog surface (#507)', () => {
  it('is what the registry renders (regenerate with `pnpm exec nx run auth-server:admin-permissions-export`)', () => {
    const path = join(REPO_ROOT, ADMIN_PERMISSIONS_SURFACE_PATH);
    expect(existsSync(path), `${ADMIN_PERMISSIONS_SURFACE_PATH} is missing`).toBe(true);
    expect(readFileSync(path, 'utf8')).toBe(adminPermissionsSurfaceText(PERMISSION_REGISTRY));
  });

  it('names every permission, retired ones included, as a required property with its one class', () => {
    const registry = createPermissionRegistry([
      ...PERMISSION_REGISTRY.all,
      definePermission({
        id: 'widgets.list',
        class: 'read',
        resource: 'widgets',
        description: 'List the widgets.',
        retiredIn: 'v0.3.0',
      }),
    ]);
    const schema = renderAdminPermissionsSurface(registry) as unknown as CatalogSchema;
    expect(schema.required).toEqual(registry.all.map((permission) => permission.id));
    for (const permission of registry.all) {
      const entry = schema.properties[permission.id];
      expect(entry.required).toEqual(['class']);
      expect(entry.properties.class.enum).toEqual([permission.class]);
    }
    expect(schema.properties['widgets.list'].properties.retiredIn?.enum).toEqual(['v0.3.0']);
    expect(schema.properties['realms.read'].properties.retiredIn).toBeUndefined();
  });

  it('is registered with the stable-surface check as a stable output schema', () => {
    const registry = JSON.parse(
      readFileSync(join(REPO_ROOT, 'stable-surface/surfaces.json'), 'utf8')
    ) as { surfaces: Record<string, unknown>[] };
    expect(registry.surfaces).toContainEqual(
      expect.objectContaining({
        name: 'admin-permissions',
        format: 'json-schema',
        role: 'output',
        generator: 'pnpm exec nx run auth-server:admin-permissions-export --skip-nx-cache',
        path: ADMIN_PERMISSIONS_SURFACE_PATH,
        stability: 'stable',
      })
    );
  });
});
