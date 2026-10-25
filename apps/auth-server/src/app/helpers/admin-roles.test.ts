import { describe, expect, it } from 'vitest';

import {
  type AdminPermission,
  createPermissionRegistry,
  definePermission,
  PERMISSION_REGISTRY,
  type PermissionRegistry,
} from './admin-permissions';
import {
  BUILT_IN_ROLE_NAMES,
  BUILT_IN_ROLES,
  builtInRolesOf,
  effectivePermissions,
  isBuiltInRoleName,
  validateCustomRole,
} from './admin-roles';
import { PERMISSION_CLASSES, type PermissionClass } from './admin-scopes';

const ids = (permissions: readonly AdminPermission[]) => permissions.map(({ id }) => id);

describe('built-in roles (#507)', () => {
  it('are viewer, editor and security-admin', () => {
    expect(BUILT_IN_ROLE_NAMES).toEqual(['viewer', 'editor', 'security-admin']);
    expect(Object.keys(BUILT_IN_ROLES)).toEqual(['viewer', 'editor', 'security-admin']);
  });

  it('viewer holds every read permission and nothing else', () => {
    expect(BUILT_IN_ROLES.viewer.permissionIds).toEqual(ids(PERMISSION_REGISTRY.ofClass('read')));
    expect(BUILT_IN_ROLES.viewer.permissionIds).toEqual([
      'realms.read',
      'realms.export',
      'realms.import.plan',
      'approvals.read',
    ]);
  });

  it('editor holds every read and write permission and no security permission', () => {
    expect(BUILT_IN_ROLES.editor.classes).toEqual(['read', 'write']);
    expect(BUILT_IN_ROLES.editor.permissionIds).toEqual([
      'realms.read',
      'realms.export',
      'realms.import.plan',
      'realms.policies.write',
      'approvals.read',
    ]);
  });

  it('security-admin holds every permission', () => {
    expect(BUILT_IN_ROLES['security-admin'].permissionIds).toEqual(ids(PERMISSION_REGISTRY.active));
  });

  it('follow the catalog: a new permission joins the roles of its class, a retired one leaves', () => {
    const registry = createPermissionRegistry([
      definePermission({
        id: 'widgets.read',
        class: 'read',
        resource: 'widgets',
        description: 'Read.',
      }),
      definePermission({
        id: 'widgets.write',
        class: 'write',
        resource: 'widgets',
        description: 'Write.',
      }),
      definePermission({
        id: 'widgets.list',
        class: 'read',
        resource: 'widgets',
        description: 'List.',
        retiredIn: 'v0.3.0',
      }),
    ]);
    const roles = builtInRolesOf(registry);
    expect(roles.viewer.permissionIds).toEqual(['widgets.read']);
    expect(roles.editor.permissionIds).toEqual(['widgets.read', 'widgets.write']);
    expect(roles['security-admin'].permissionIds).toEqual(['widgets.read', 'widgets.write']);
  });

  it('cannot be edited', () => {
    expect(Object.isFrozen(BUILT_IN_ROLES)).toBe(true);
    expect(Object.isFrozen(BUILT_IN_ROLE_NAMES)).toBe(true);
    for (const name of BUILT_IN_ROLE_NAMES) {
      const role = BUILT_IN_ROLES[name];
      expect(Object.isFrozen(role)).toBe(true);
      expect(Object.isFrozen(role.permissionIds)).toBe(true);
      expect(Object.isFrozen(role.classes)).toBe(true);
    }
    expect(() => {
      (BUILT_IN_ROLES.viewer.permissionIds as string[]).push('realms.policies.security');
    }).toThrow(TypeError);
    expect(() => {
      (BUILT_IN_ROLES as Record<string, unknown>)['viewer'] = BUILT_IN_ROLES['security-admin'];
    }).toThrow(TypeError);
    expect(BUILT_IN_ROLES.viewer.permissionIds).not.toContain('realms.policies.security');
  });

  it('reserve their names', () => {
    expect(isBuiltInRoleName('viewer')).toBe(true);
    expect(isBuiltInRoleName('security-admin')).toBe(true);
    expect(isBuiltInRoleName('Viewer')).toBe(false);
    expect(isBuiltInRoleName('auditor')).toBe(false);
  });
});

describe('validateCustomRole (#507)', () => {
  it('accepts known ids, security permissions included, each once in catalog order', () => {
    expect(
      validateCustomRole([
        'approvals.approve',
        'realms.read',
        'realms.read',
        'realms.policies.security',
      ])
    ).toEqual({
      valid: true,
      permissionIds: ['realms.read', 'realms.policies.security', 'approvals.approve'],
    });
  });

  it('accepts a known id', () => {
    expect(validateCustomRole(['realms.read'])).toEqual({
      valid: true,
      permissionIds: ['realms.read'],
    });
  });

  it('refuses an unknown id and names it', () => {
    expect(validateCustomRole(['realms.read', 'realms.delete'])).toEqual({
      valid: false,
      unknownIds: ['realms.delete'],
      retiredIds: [],
    });
  });

  it.each([['Realms.read'], ['realms.read '], ['admin:read'], ['realms'], ['']])(
    'refuses %j: ids match exactly',
    (id) => {
      expect(validateCustomRole([id])).toMatchObject({ valid: false, unknownIds: [id] });
    }
  );

  it('refuses a value that is not a string', () => {
    expect(validateCustomRole([42 as unknown as string])).toMatchObject({
      valid: false,
      unknownIds: ['42'],
    });
  });

  it('refuses a retired permission: no role may list it any more', () => {
    const registry = createPermissionRegistry([
      definePermission({
        id: 'widgets.read',
        class: 'read',
        resource: 'widgets',
        description: 'Read.',
      }),
      definePermission({
        id: 'widgets.list',
        class: 'read',
        resource: 'widgets',
        description: 'List.',
        retiredIn: 'v0.3.0',
      }),
    ]);
    expect(validateCustomRole(['widgets.read', 'widgets.list'], registry)).toEqual({
      valid: false,
      unknownIds: [],
      retiredIds: ['widgets.list'],
    });
  });
});

describe('effectivePermissions (#507)', () => {
  const all = BUILT_IN_ROLES['security-admin'].permissionIds;

  it('keeps the read permissions for admin:read', () => {
    expect([...effectivePermissions(all, 'admin:read')]).toEqual(
      BUILT_IN_ROLES.viewer.permissionIds
    );
  });

  // Acceptance criterion of #507: the three scopes are independent.
  it('admin:write does not satisfy a read permission', () => {
    expect(effectivePermissions(['realms.read'], 'admin:write').size).toBe(0);
    expect([...effectivePermissions(all, 'admin:write')]).toEqual(['realms.policies.write']);
  });

  it('admin:security satisfies neither a read nor a write permission', () => {
    expect(
      effectivePermissions(['realms.read', 'realms.policies.write'], 'admin:security').size
    ).toBe(0);
    expect([...effectivePermissions(all, ['admin:security'])]).toEqual([
      'realms.policies.security',
      'approvals.approve',
    ]);
  });

  it('needs both scopes for a request that needs a write and a security permission', () => {
    const needed = ['realms.policies.write', 'realms.policies.security'];
    const hasAll = (scopes: string) =>
      needed.every((id) => effectivePermissions(all, scopes).has(id));
    expect(hasAll('admin:write')).toBe(false);
    expect(hasAll('admin:security')).toBe(false);
    expect(hasAll('admin:write admin:security')).toBe(true);
  });

  it('grants nothing a role does not hold, whatever the scopes', () => {
    expect([
      ...effectivePermissions(
        BUILT_IN_ROLES.viewer.permissionIds,
        'admin:read admin:write admin:security'
      ),
    ]).toEqual(BUILT_IN_ROLES.viewer.permissionIds);
  });

  it('grants nothing for an unknown or retired id, or a scope that only looks like an admin scope', () => {
    const registry = createPermissionRegistry([
      definePermission({
        id: 'widgets.list',
        class: 'read',
        resource: 'widgets',
        description: 'List.',
        retiredIn: 'v0.3.0',
      }),
    ]);
    expect(effectivePermissions(['widgets.list'], 'admin:read', registry).size).toBe(0);
    expect(effectivePermissions(['realms.delete', 'Realms.read'], 'admin:read').size).toBe(0);
    expect(
      effectivePermissions(all, 'Admin:read ADMIN:SECURITY admin:Write agent:admin').size
    ).toBe(0);
    expect(effectivePermissions(all, '').size).toBe(0);
  });

  it('refuses a string where the list of role permissions belongs', () => {
    expect(() => effectivePermissions('realms.read' as unknown as string[], 'admin:read')).toThrow(
      TypeError
    );
  });
});

/**
 * The property of #507's first acceptance criterion: a token with only
 * `admin:write` never gets a security-class permission, for any role.
 *
 * The repository has no property-testing library, and the property needs
 * none: for the real catalog every role (every subset of its ids, plus ids it
 * does not know) is enumerated outright, and for catalogs other issues may
 * grow into, seeded random catalogs and roles are generated. A failure prints
 * the seed and the case.
 */
describe('property: admin:write alone never reaches a security permission (#507)', () => {
  /** mulberry32: a small, seeded generator, so a failing case reproduces. */
  function generator(seed: number) {
    let state = seed >>> 0;
    const next = () => {
      state = (state + 0x6d2b79f5) >>> 0;
      let t = state;
      t = Math.imul(t ^ (t >>> 15), t | 1);
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
    return {
      next,
      int: (max: number) => Math.floor(next() * max),
      pick: <T>(items: readonly T[]) => items[Math.floor(next() * items.length)],
    };
  }

  /** Scopes that may sit beside `admin:write` without being `admin:security`. */
  const COMPANION_SCOPES = [
    'openid',
    'profile',
    'offline_access',
    'agent:admin',
    'agent:exec',
    'Admin:security',
    'ADMIN:SECURITY',
    'admin:securit',
    'admin:Security',
    'security',
    'admin:',
    'admin:admin',
  ];

  /** Every token whose only admin scope is `admin:write`, as a list and as a claim. */
  function writeOnlyTokens(
    random: ReturnType<typeof generator>,
    count: number
  ): (string | string[])[] {
    const tokens: (string | string[])[] = [['admin:write'], 'admin:write'];
    for (let i = 0; i < count; i++) {
      const scopes = ['admin:write'];
      const extra = random.int(5);
      for (let j = 0; j < extra; j++) scopes.push(random.pick(COMPANION_SCOPES));
      scopes.sort(() => random.next() - 0.5);
      tokens.push(random.next() < 0.5 ? scopes : scopes.join(' '));
    }
    // In a list, an entry with white space is one scope that only looks like
    // `admin:security`; joined into a claim it would be the real one.
    tokens.push(['admin:write', 'admin:security ', ' admin:security']);
    return tokens;
  }

  function assertNoSecurity(
    registry: PermissionRegistry,
    role: readonly string[],
    token: string | string[],
    context: string
  ) {
    for (const id of effectivePermissions(role, token, registry)) {
      const permission = registry.get(id);
      expect(
        permission?.class,
        `${context}: role ${JSON.stringify(role)} with token ${JSON.stringify(token)} reached ${id}`
      ).not.toBe('security');
    }
  }

  it('holds for every role over the real catalog', () => {
    const random = generator(507);
    const tokens = writeOnlyTokens(random, 40);
    const catalog = ids(PERMISSION_REGISTRY.all);
    // Ids a stored role might still carry: unknown, look-alike, malformed.
    const strays = [
      'realms.delete',
      'Realms.policies.security',
      'approvals.approve ',
      'admin:security',
    ];
    const universe = [...catalog, ...strays];
    expect(universe.length).toBeLessThanOrEqual(16);
    let checked = 0;
    for (let mask = 0; mask < 1 << universe.length; mask++) {
      const role = universe.filter((_, bit) => (mask & (1 << bit)) !== 0);
      for (const token of tokens) {
        assertNoSecurity(PERMISSION_REGISTRY, role, token, 'real catalog');
        checked++;
      }
    }
    // The security-admin role, with every security permission, is among them.
    expect(checked).toBe((1 << universe.length) * tokens.length);
  });

  it('holds for seeded random catalogs and roles', () => {
    for (let seed = 1; seed <= 200; seed++) {
      const random = generator(seed);
      const size = 1 + random.int(24);
      const permissions: AdminPermission[] = [];
      for (let i = 0; i < size; i++) {
        const permissionClass: PermissionClass = random.pick(PERMISSION_CLASSES);
        const resource = `resource${random.int(5)}`;
        permissions.push(
          definePermission({
            id: `${resource}.action${i}`,
            class: permissionClass,
            resource,
            description: `Permission ${i}.`,
            ...(random.next() < 0.1 ? { retiredIn: 'v0.3.0' as const } : {}),
          })
        );
      }
      const registry = createPermissionRegistry(permissions);
      const tokens = writeOnlyTokens(random, 10);
      const roles: string[][] = [
        ids(registry.all),
        ids(registry.ofClass('security')),
        ...Object.values(builtInRolesOf(registry)).map((role) => [...role.permissionIds]),
      ];
      for (let r = 0; r < 20; r++) {
        roles.push(ids(registry.all).filter(() => random.next() < 0.5));
      }
      for (const role of roles) {
        for (const token of tokens) assertNoSecurity(registry, role, token, `seed ${seed}`);
      }
    }
  });

  it('would catch a broken intersection: the same roles do reach security with admin:security', () => {
    const reached = effectivePermissions(
      BUILT_IN_ROLES['security-admin'].permissionIds,
      'admin:write admin:security'
    );
    expect([...reached].some((id) => PERMISSION_REGISTRY.get(id)?.class === 'security')).toBe(true);
  });
});
