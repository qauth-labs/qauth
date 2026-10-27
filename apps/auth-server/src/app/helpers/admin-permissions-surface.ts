import type { PermissionRegistry } from './admin-permissions';

/**
 * The admin permission catalog as a stable surface (#507): a JSON Schema that
 * `scripts/stable-surface/check.mjs` compares with the latest release, so a
 * permission that is removed or changes its class is a break the check
 * reports, however often the docs page is regenerated.
 *
 * Each permission, retired ones included, is a required property named by its
 * id, whose `class` is a one-value enum. The check wraps an `output` surface
 * as a response, where oasdiff rates a removed property
 * (`response-required-property-removed`) and an added enum value
 * (`response-property-enum-value-added`, which a changed class is) as breaks.
 * A new permission is an added property, and retiring one adds the optional
 * `retiredIn`; neither is a break.
 *
 * `pnpm exec nx run auth-server:admin-permissions-export` writes the file;
 * `admin-permissions-surface.test.ts` fails while the committed one differs.
 */

/** The surface, from the repository root. */
export const ADMIN_PERMISSIONS_SURFACE_PATH =
  'apps/docs-site/public/schemas/admin-permissions.json';

/** The JSON Schema of the catalog in `registry`. */
export function renderAdminPermissionsSurface(
  registry: PermissionRegistry
): Record<string, unknown> {
  const properties: Record<string, unknown> = {};
  for (const permission of registry.all) {
    properties[permission.id] = {
      type: 'object',
      required: ['class'],
      properties: {
        class: { type: 'string', enum: [permission.class] },
        ...(permission.retiredIn === undefined
          ? {}
          : { retiredIn: { type: 'string', enum: [permission.retiredIn] } }),
      },
    };
  }
  return {
    $schema: 'https://json-schema.org/draft/2020-12/schema',
    $id: 'https://docs.qauth.dev/schemas/admin-permissions.json',
    title: 'QAuth admin permission catalog',
    description:
      'Every permission of the admin API, retired ones included, by id, with its class and the release that retired it. Generated from apps/auth-server/src/app/helpers/admin-permissions.ts; the stable-surface check reports a removed permission or a changed class as a break. The ids are promised from 1.0.0 on (ADR-018 §5).',
    type: 'object',
    required: registry.all.map((permission) => permission.id),
    properties,
  };
}

/** The file's text: `JSON.stringify` output with a final newline, as the other generated schemas. */
export function adminPermissionsSurfaceText(registry: PermissionRegistry): string {
  return `${JSON.stringify(renderAdminPermissionsSurface(registry), null, 2)}\n`;
}
