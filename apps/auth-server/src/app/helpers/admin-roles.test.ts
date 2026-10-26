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
  builtInRoleNameOf,
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
    expect(isBuiltInRoleName('editor')).toBe(true);
    expect(isBuiltInRoleName('security-admin')).toBe(true);
    expect(isBuiltInRoleName('auditor')).toBe(false);
  });

  // A custom role named like a built-in one would read as it in the console.
  it.each([
    ['Viewer', 'viewer'],
    ['EDITOR', 'editor'],
    ['  viewer  ', 'viewer'],
    ['Security-Admin', 'security-admin'],
    ['security admin', 'security-admin'],
    ['security_admin', 'security-admin'],
    ['security\u2011admin', 'security-admin'],
    ['security\u2014admin', 'security-admin'],
    ['security \u2212 admin', 'security-admin'],
    ['\uff56\uff49\uff45\uff57\uff45\uff52', 'viewer'],
    ['vi\u0308ewer', 'viewer'],
    ['VI\u0307EWER', 'viewer'],
    ['edi\u200btor', 'editor'],
    ['secur\u00adity-admin', 'security-admin'],
  ])('reserve %j, which reads as %s', (name, builtIn) => {
    expect(builtInRoleNameOf(name)).toBe(builtIn);
    expect(isBuiltInRoleName(name)).toBe(true);
  });

  it.each(['auditor', 'viewers', 'security-admins', 'securityadmin', 'admin', '', '-'])(
    'leave %j to custom roles',
    (name) => {
      expect(builtInRoleNameOf(name)).toBeUndefined();
      expect(isBuiltInRoleName(name)).toBe(false);
    }
  );
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

  it.each([['Realms.read'], ['realms.read '], ['qauth:admin:read'], ['realms'], ['']])(
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

  it('keeps the read permissions for qauth:admin:read', () => {
    expect([...effectivePermissions(all, 'qauth:admin:read')]).toEqual(
      BUILT_IN_ROLES.viewer.permissionIds
    );
  });

  // Acceptance criterion of #507: the three scopes are independent.
  it('qauth:admin:write does not satisfy a read permission', () => {
    expect(effectivePermissions(['realms.read'], 'qauth:admin:write').size).toBe(0);
    expect([...effectivePermissions(all, 'qauth:admin:write')]).toEqual(['realms.policies.write']);
  });

  it('qauth:admin:security satisfies neither a read nor a write permission', () => {
    expect(
      effectivePermissions(['realms.read', 'realms.policies.write'], 'qauth:admin:security').size
    ).toBe(0);
    expect([...effectivePermissions(all, ['qauth:admin:security'])]).toEqual([
      'realms.policies.security',
      'approvals.approve',
    ]);
  });

  it('needs both scopes for a request that needs a write and a security permission', () => {
    const needed = ['realms.policies.write', 'realms.policies.security'];
    const hasAll = (scopes: string) =>
      needed.every((id) => effectivePermissions(all, scopes).has(id));
    expect(hasAll('qauth:admin:write')).toBe(false);
    expect(hasAll('qauth:admin:security')).toBe(false);
    expect(hasAll('qauth:admin:write qauth:admin:security')).toBe(true);
  });

  it('grants nothing a role does not hold, whatever the scopes', () => {
    expect([
      ...effectivePermissions(
        BUILT_IN_ROLES.viewer.permissionIds,
        'qauth:admin:read qauth:admin:write qauth:admin:security'
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
    expect(effectivePermissions(['widgets.list'], 'qauth:admin:read', registry).size).toBe(0);
    expect(effectivePermissions(['realms.delete', 'Realms.read'], 'qauth:admin:read').size).toBe(0);
    expect(
      effectivePermissions(
        all,
        'QAuth:admin:read qauth:ADMIN:SECURITY qauth:admin:Write admin:read admin:security agent:admin'
      ).size
    ).toBe(0);
    expect(effectivePermissions(all, '').size).toBe(0);
  });

  it('refuses a string where the list of role permissions belongs', () => {
    expect(() =>
      effectivePermissions('realms.read' as unknown as string[], 'qauth:admin:read')
    ).toThrow(TypeError);
  });
});

/**
 * The property of #507's first acceptance criterion: a token with only
 * `qauth:admin:write` never gets a security-class permission, for any role.
 *
 * The repository has no property-testing library, and the property needs
 * none: for the real catalog every role (every subset of its ids, plus ids it
 * does not know) is enumerated outright, and for catalogs other issues may
 * grow into, seeded random catalogs and roles are generated. A failure prints
 * the seed and the case.
 */
describe('property: qauth:admin:write alone never reaches a security permission (#507)', () => {
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

  /** Scopes that may sit beside `qauth:admin:write` without being `qauth:admin:security`. */
  const COMPANION_SCOPES = [
    'openid',
    'profile',
    'offline_access',
    'agent:admin',
    'agent:exec',
    'QAuth:admin:security',
    'QAUTH:ADMIN:SECURITY',
    'qauth:admin:securit',
    'qauth:admin:Security',
    'admin:security',
    'security',
    'qauth:admin:',
    'qauth:admin:admin',
  ];

  /** Every token whose only admin scope is `qauth:admin:write`, as a list and as a claim. */
  function writeOnlyTokens(
    random: ReturnType<typeof generator>,
    count: number
  ): (string | string[])[] {
    const tokens: (string | string[])[] = [['qauth:admin:write'], 'qauth:admin:write'];
    for (let i = 0; i < count; i++) {
      const scopes = ['qauth:admin:write'];
      const extra = random.int(5);
      for (let j = 0; j < extra; j++) scopes.push(random.pick(COMPANION_SCOPES));
      scopes.sort(() => random.next() - 0.5);
      tokens.push(random.next() < 0.5 ? scopes : scopes.join(' '));
    }
    // In a list, an entry with white space is one scope that only looks like
    // `qauth:admin:security`; joined into a claim it would be the real one.
    tokens.push(['qauth:admin:write', 'qauth:admin:security ', ' qauth:admin:security']);
    return tokens;
  }

  /**
   * The security permissions `role` reaches with `token`, each described for
   * the failure message; the property holds when there are none. Collected and
   * asserted once per test: one `expect` per permission made the seeded run
   * slow enough to time out on a loaded runner.
   */
  function securityReached(
    registry: PermissionRegistry,
    role: readonly string[],
    token: string | string[],
    context: string
  ): string[] {
    return [...effectivePermissions(role, token, registry)]
      .filter((id) => registry.get(id)?.class === 'security')
      .map(
        (id) =>
          `${context}: role ${JSON.stringify(role)} with token ${JSON.stringify(token)} reached ${id}`
      );
  }

  /** Up to this many ids every subset is a role (4,096 of them); past it, roles are sampled. */
  const EXHAUSTIVE_UNIVERSE_MAX = 12;
  /** How many roles a sample holds once the universe outgrows enumeration. */
  const SAMPLED_ROLES = 4096;

  /**
   * The roles over `universe` the property is checked for: every subset while
   * there are at most {@link EXHAUSTIVE_UNIVERSE_MAX} ids, so the catalog can
   * grow without the test growing as 2^n; then the whole universe, each
   * built-in role and seeded random subsets.
   */
  function rolesOver(
    universe: readonly string[],
    random: ReturnType<typeof generator>,
    registry: PermissionRegistry
  ): string[][] {
    if (universe.length <= EXHAUSTIVE_UNIVERSE_MAX) {
      const roles: string[][] = [];
      for (let mask = 0; mask < 1 << universe.length; mask++) {
        roles.push(universe.filter((_, bit) => (mask & (1 << bit)) !== 0));
      }
      return roles;
    }
    const roles: string[][] = [
      [...universe],
      ...Object.values(builtInRolesOf(registry)).map((role) => [...role.permissionIds]),
    ];
    while (roles.length < SAMPLED_ROLES) roles.push(universe.filter(() => random.next() < 0.5));
    return roles;
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
      'qauth:admin:security',
    ];
    const roles = rolesOver([...catalog, ...strays], random, PERMISSION_REGISTRY);
    const reached: string[] = [];
    for (const role of roles) {
      for (const token of tokens) {
        reached.push(...securityReached(PERMISSION_REGISTRY, role, token, 'real catalog'));
      }
    }
    expect(reached).toEqual([]);
    // The security-admin role, with every security permission, is among them.
    const securityAdmin = BUILT_IN_ROLES['security-admin'].permissionIds;
    expect(roles.some((role) => securityAdmin.every((id) => role.includes(id)))).toBe(true);
  });

  it('samples the roles of a catalog too large to enumerate, the widest role included', () => {
    const permissions = Array.from({ length: 20 }, (_, i) =>
      definePermission({
        id: `widgets.action${i}`,
        class: PERMISSION_CLASSES[i % 3],
        resource: 'widgets',
        description: `Permission ${i}.`,
      })
    );
    const registry = createPermissionRegistry(permissions);
    const universe = ids(registry.all);
    const roles = rolesOver(universe, generator(1), registry);
    expect(roles).toHaveLength(SAMPLED_ROLES);
    expect(roles[0]).toEqual(universe);
    expect(roles).toContainEqual([...builtInRolesOf(registry)['security-admin'].permissionIds]);
  });

  it('holds for seeded random catalogs and roles', () => {
    const reached: string[] = [];
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
        for (const token of tokens) {
          reached.push(...securityReached(registry, role, token, `seed ${seed}`));
        }
      }
    }
    expect(reached).toEqual([]);
  });

  it('would catch a broken intersection: the same roles do reach security with qauth:admin:security', () => {
    const reached = effectivePermissions(
      BUILT_IN_ROLES['security-admin'].permissionIds,
      'qauth:admin:write qauth:admin:security'
    );
    expect([...reached].some((id) => PERMISSION_REGISTRY.get(id)?.class === 'security')).toBe(true);
  });
});
