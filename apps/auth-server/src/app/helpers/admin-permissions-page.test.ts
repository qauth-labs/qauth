import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join } from 'node:path';

import { beforeAll, describe, expect, it } from 'vitest';

import {
  type AdminPermission,
  createPermissionRegistry,
  definePermission,
  PERMISSION_REGISTRY,
} from './admin-permissions';
import { ADMIN_PERMISSIONS_PAGE_PATH, renderAdminPermissionsPage } from './admin-permissions-page';
import { BUILT_IN_ROLES, builtInRolesOf } from './admin-roles';
import { ADMIN_SCOPES } from './admin-scopes';

/**
 * The docs page `reference/admin-permissions.md` is generated from the
 * permission registry (#507). This test is the generator: when the registry
 * changes, `pnpm nx test auth-server -- -u` rewrites the page, and without
 * `-u` the test fails until the committed page matches.
 *
 * The rendered page goes through Oxfmt first, so the committed file is
 * already formatted and the formatter never rewrites it.
 */

const REPO_ROOT = join(__dirname, '..', '..', '..', '..', '..');
const PAGE_PATH = join(REPO_ROOT, ADMIN_PERMISSIONS_PAGE_PATH);

/** Oxfmt's command line, which formats with the repository's `.oxfmtrc.json`. */
const OXFMT = join(
  dirname(createRequire(__filename).resolve('oxfmt/package.json')),
  'bin',
  'oxfmt'
);

/** `text` as Oxfmt formats the file at `path`. */
function formatAs(path: string, text: string): string {
  return execFileSync(process.execPath, [OXFMT, `--stdin-filepath=${path}`], {
    cwd: REPO_ROOT,
    input: text,
    encoding: 'utf8',
  });
}

/** The body of the `## <heading>` section, up to the next one. */
function sectionOf(page: string, heading: string): string {
  const start = page.indexOf(`\n## ${heading}\n`);
  if (start === -1) return '';
  const next = page.indexOf('\n## ', start + 1);
  return page.slice(start, next === -1 ? undefined : next);
}

/** The rows of a table in `section`, as trimmed cells, without the header and the rule. */
function tableRows(section: string): string[][] {
  return section
    .split('\n')
    .filter((line) => line.startsWith('|'))
    .slice(2)
    .map((line) =>
      line
        .slice(1, -1)
        .split(/(?<!\\)\|/)
        .map((cell) => cell.trim())
    );
}

/**
 * The page as committed, read when the file is collected: before `-u` can
 * rewrite it, so a published id that left the registry still fails the run
 * that regenerates the page.
 */
const COMMITTED_PAGE = existsSync(PAGE_PATH) ? readFileSync(PAGE_PATH, 'utf8') : '';

let page = '';
beforeAll(() => {
  page = formatAs(PAGE_PATH, renderAdminPermissionsPage(PERMISSION_REGISTRY, BUILT_IN_ROLES));
});

describe('the admin permissions page (#507)', () => {
  it('is what the registry renders (regenerate with `pnpm nx test auth-server -- -u`)', async () => {
    await expect(page).toMatchFileSnapshot(PAGE_PATH);
  });

  it('carries the frontmatter the docs collection requires', () => {
    expect(page).toMatch(
      /^---\ntitle: Admin permissions\ndescription: .+\nsidebar:\n {2}order: \d+\nlastVerified: '\d{4}-\d{2}-\d{2}'\n---\n/
    );
  });

  // Acceptance criterion of #507: the generated page lists every registered
  // permission with its class.
  it('lists every registered permission with its class and scope, and nothing else', () => {
    const rows = tableRows(sectionOf(page, 'Permissions'));
    expect(rows.map(([id, permissionClass, scope]) => [id, permissionClass, scope])).toEqual(
      PERMISSION_REGISTRY.active.map((permission) => [
        `\`${permission.id}\``,
        permission.class,
        `\`${ADMIN_SCOPES[permission.class]}\``,
      ])
    );
    for (const permission of PERMISSION_REGISTRY.active) {
      expect(page).toContain(permission.description);
    }
  });

  it('lists each built-in role with exactly its permissions', () => {
    const rows = tableRows(sectionOf(page, 'Built-in roles'));
    expect(rows.map(([name, , permissions]) => [name, permissions])).toEqual(
      Object.values(BUILT_IN_ROLES).map((role) => [
        `\`${role.name}\``,
        role.permissionIds.map((id) => `\`${id}\``).join(', '),
      ])
    );
  });

  it('lists the three scopes', () => {
    expect(tableRows(sectionOf(page, 'Scopes')).map(([scope]) => scope)).toEqual([
      '`admin:read`',
      '`admin:write`',
      '`admin:security`',
    ]);
  });

  // A published id is never removed and never given another meaning: a
  // permission that is no longer needed is retired (`retiredIn`), so its id
  // stays taken and the page keeps it, and its class never changes, or every
  // stored custom role that lists it would reach it with another scope. The
  // committed page is read before `-u` rewrites it, so the run that
  // regenerates the page fails too; a later run reads the rewritten page,
  // which is why the page's diff is the change a reviewer checks.
  it('still registers every permission the committed page publishes, with its class', () => {
    const published = [
      ...tableRows(sectionOf(COMMITTED_PAGE, 'Permissions')),
      ...tableRows(sectionOf(COMMITTED_PAGE, 'Retired permissions')),
    ].map(([id, permissionClass]) => ({ id: id.replace(/`/g, ''), class: permissionClass }));
    expect(published.length).toBeGreaterThan(0);
    const changed = published.filter(
      (entry) => PERMISSION_REGISTRY.get(entry.id)?.class !== entry.class
    );
    expect(
      changed,
      'a published permission was removed or changed its class: retire it with retiredIn and define a new id instead'
    ).toEqual([]);
  });

  it('says that no permission has been retired yet', () => {
    expect(sectionOf(page, 'Retired permissions')).toContain('No permission has been retired.');
  });
});

describe('renderAdminPermissionsPage', () => {
  const widget = (permission: Partial<AdminPermission> & Pick<AdminPermission, 'id'>) =>
    definePermission({
      class: 'read',
      resource: 'widgets',
      description: 'Read the widgets.',
      ...permission,
    });

  it('renders a permission another issue adds, and moves a retired one to its own table', () => {
    const registry = createPermissionRegistry([
      ...PERMISSION_REGISTRY.all,
      widget({ id: 'widgets.read' }),
      widget({ id: 'widgets.rotate', class: 'security', description: 'Rotate a | widget.' }),
      widget({ id: 'widgets.list', description: 'List the widgets.', retiredIn: 'v0.3.0' }),
    ]);
    const rendered = renderAdminPermissionsPage(registry, builtInRolesOf(registry));
    const permissions = tableRows(sectionOf(rendered, 'Permissions')).map(([id, cls]) => [id, cls]);
    expect(permissions).toContainEqual(['`widgets.read`', 'read']);
    expect(permissions).toContainEqual(['`widgets.rotate`', 'security']);
    expect(permissions).not.toContainEqual(['`widgets.list`', 'read']);
    expect(rendered).toContain('Rotate a \\| widget.');
    expect(tableRows(sectionOf(rendered, 'Retired permissions'))).toEqual([
      ['`widgets.list`', 'read', 'v0.3.0', 'List the widgets.'],
    ]);
  });
});
