import type { AdminPermission, PermissionRegistry } from './admin-permissions';
import { ADMIN_PERMISSIONS_SURFACE_PATH } from './admin-permissions-surface';
import type { BuiltInRole, BuiltInRoleName } from './admin-roles';
import {
  ADMIN_SCOPES,
  PERMISSION_CLASSES,
  type PermissionClass,
  QAUTH_SCOPE_NAMESPACE,
} from './admin-scopes';

/**
 * The docs page `reference/admin-permissions.md`, rendered from the permission
 * registry and the built-in roles (#507). Generated, never edited by hand:
 * `pnpm nx test auth-server -- -u` rewrites it, and
 * `admin-permissions-page.test.ts` fails while the committed page differs.
 */

/** The page, from the repository root. */
export const ADMIN_PERMISSIONS_PAGE_PATH =
  'apps/docs-site/src/content/docs/reference/admin-permissions.md';

/** The date the page's hand-written prose was last checked; change it with the prose. */
export const ADMIN_PERMISSIONS_PAGE_LAST_VERIFIED = '2026-10-26';

/** Where the registry lives, as the page names it. */
const REGISTRY_PATH = 'apps/auth-server/src/app/helpers/admin-permissions.ts';

const code = (value: string) => `\`${value}\``;

/**
 * A table cell: backslashes and pipes escaped, newlines flattened. The
 * backslash goes first, or a `\|` in the text would end the cell.
 */
const tableCell = (value: string) =>
  value
    .replace(/\\/g, '\\\\')
    .replace(/\|/g, '\\|')
    .replace(/\s+/g, (run) => (run.includes('\n') ? ' ' : run));

const CLASS_MEANING: Readonly<Record<PermissionClass, string>> = {
  read: 'Reads configuration and state. Changes nothing.',
  write:
    'Changes display data and operational settings, with none of the effects of a security operation.',
  security:
    'Performs a security operation, defined by its effect in ADR-019 Decision 7, such as changing what can authenticate an account or what a token asserts.',
};

/** The Scopes table: each admin scope, the class it allows and what that class means. */
function scopeTable(): string {
  const lines = ['| Scope | Allows | Meaning |', '| --- | --- | --- |'];
  for (const permissionClass of PERMISSION_CLASSES) {
    lines.push(
      `| ${code(ADMIN_SCOPES[permissionClass])} | ${permissionClass} permissions | ${tableCell(CLASS_MEANING[permissionClass])} |`
    );
  }
  return lines.join('\n');
}

function permissionRow(permission: AdminPermission): string {
  return `| ${code(permission.id)} | ${permission.class} | ${code(ADMIN_SCOPES[permission.class])} | ${code(permission.resource)} | ${tableCell(permission.description)} |`;
}

/** The Permissions table: one row per grantable permission, in catalog order. */
function permissionTable(permissions: readonly AdminPermission[]): string {
  return [
    '| Permission | Class | Scope | Resource | Description |',
    '| --- | --- | --- | --- | --- |',
    ...permissions.map(permissionRow),
  ].join('\n');
}

/** The Built-in roles table: each role's classes and the permission ids it grants. */
function roleTable(roles: Readonly<Record<BuiltInRoleName, BuiltInRole>>): string {
  const lines = ['| Role | Classes | Permissions | Description |', '| --- | --- | --- | --- |'];
  for (const role of Object.values(roles)) {
    const permissions =
      role.permissionIds.length === 0 ? 'none' : role.permissionIds.map(code).join(', ');
    lines.push(
      `| ${code(role.name)} | ${role.classes.join(', ')} | ${permissions} | ${tableCell(role.description)} |`
    );
  }
  return lines.join('\n');
}

/** The Retired permissions section: a table, or a sentence when none is retired. */
function retiredSection(retired: readonly AdminPermission[]): string {
  if (retired.length === 0) {
    return 'No permission has been retired.';
  }
  return [
    '| Permission | Class | Retired in | Description |',
    '| --- | --- | --- | --- |',
    ...retired.map(
      (permission) =>
        `| ${code(permission.id)} | ${permission.class} | ${permission.retiredIn} | ${tableCell(permission.description)} |`
    ),
  ].join('\n');
}

/**
 * The whole page, before formatting, rendered from `registry` and the built-in
 * `roles` over it. The test that generates the page formats it with Oxfmt and
 * compares it with the committed file.
 */
export function renderAdminPermissionsPage(
  registry: PermissionRegistry,
  roles: Readonly<Record<BuiltInRoleName, BuiltInRole>>
): string {
  const retired = registry.all.filter((permission) => permission.retiredIn !== undefined);
  return `---
title: Admin permissions
description: The admin scopes, every permission of the admin API with its class, and the built-in admin roles, generated from the registry in apps/auth-server.
sidebar:
  order: 6
lastVerified: '${ADMIN_PERMISSIONS_PAGE_LAST_VERIFIED}'
---

<!-- Generated from ${REGISTRY_PATH} by its tests. Do not edit by hand: change the registry and run \`pnpm nx test auth-server -- -u\`. -->

The admin API is to authorize each request by scope and by role
([ADR-019](/reference/records/adr/019-deployment-topology-and-trust-boundaries/), Decision 7).
A role grants permissions. The token's scopes decide which classes of those permissions this
token may use. This page lists the scopes, every permission and the built-in roles, and states
the rule the admin API will enforce. No admin API route reads the catalog yet, so the rule
protects nothing today; the \`qauth:\` scope namespace is already reserved, as listed below. The page is
generated from the registry in \`${REGISTRY_PATH}\`.

## Scopes

${scopeTable()}

- The three scopes are independent. No scope implies another: \`${ADMIN_SCOPES.write}\` does not
  satisfy a read permission, and \`${ADMIN_SCOPES.security}\` satisfies neither a read nor a write
  permission.
- A request that needs a write permission and a security permission needs both scopes.
- Scopes are matched exactly and case-sensitively (RFC 6749 §3.3).
- Every scope in the \`${QAUTH_SCOPE_NAMESPACE}\` namespace, in any case, is QAuth's. A realm's dynamic
  registration allowlist cannot hold one, so dynamic registration drops one like any other scope
  outside the allowlist, and the developer API refuses one with \`invalid_client_metadata\`. A
  Client ID Metadata Document's \`scope\` is never stored, so one there is ignored. Discovery
  never lists one. Other servers' scopes such as \`admin:org\` are ordinary scopes.

## How a request is authorized

Under the rule the admin API will enforce, a permission is effective for a request when both
hold:

1. one of the caller's admin roles grants it, and
2. the token carries the scope of its class.

So a token with only \`${ADMIN_SCOPES.write}\` never uses a security permission, whatever role the caller
holds. An admin API operation names the permission it needs in its \`x-qauth-permission\`
extension ([API conventions](/reference/api-conventions/#openapi)). An operation whose request
decides whether it is a security operation, such as a policy patch, names a write permission and
a security permission, and a request that touches both needs both.

The caller's roles come from its admin grants, which name a role and a realm, or every realm. They
are read from the database on every request, never from the token, so a revoked grant counts from
the next request ([Admin authority](/reference/api-conventions/#admin-authority)). The token
endpoint already applies the scope side: it issues an admin scope only to an account whose live
grants reach that scope's class, through a client that lists the admin API's audience.

## Permissions

${permissionTable(registry.active)}

A permission has exactly one class. A permission that performs a security operation has an id of
its own and the class \`security\`; it never shares an id with a write permission, so no custom
role reaches a security operation through \`${ADMIN_SCOPES.write}\`.

## Built-in roles

${roleTable(roles)}

- Built-in roles are defined in code, by class, and cannot be edited. A permission added to the
  catalog joins every built-in role of its class.
- A custom role lists permission ids from the table above. An unknown id is refused, and so is a
  retired one. Its name is lower-case ASCII words joined by single hyphens, such as
  \`realm-auditor\`, and never reads as a built-in role's name.
- A custom role is defined in one realm, and granted only to that realm's accounts or for that
  realm. Disabling it takes its permissions from every grant at the next request.
- Admin roles are not the realm's application roles, which reach tokens as claims
  ([ADR-020](/reference/records/adr/020-ui-surfaces-and-acceptance-criteria/), fork D).

## Retired permissions

${retiredSection(retired)}

## Stability

The permission ids will be part of the admin API's contract, because custom roles store them.
Like every QAuth-defined identifier, they are promised from 1.0.0 on
([ADR-018 §5](/reference/records/adr/018-1-0-scope-and-stability/)); until then a release may still
rename one, and says so in its changelog. From 1.0.0:

- An id is never renamed and never reused for another meaning.
- A permission that is no longer needed is retired, not removed: it is listed under
  [Retired permissions](#retired-permissions), it grants nothing, and its id stays taken.
- A release may add permissions. A new permission joins the built-in roles of its class.

The stable-surface check compares the catalog's JSON Schema
(\`${ADMIN_PERMISSIONS_SURFACE_PATH}\`) with the latest release: a removed permission, or one whose
class changed, is a break it reports.
`;
}
