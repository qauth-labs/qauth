import { describe, expect, it } from 'vitest';

import {
  ADMIN_PERMISSIONS,
  type AdminPermission,
  createPermissionRegistry,
  definePermission,
  PERMISSION_ID_PATTERN,
  PERMISSION_REGISTRY,
  PermissionDefinitionError,
} from './admin-permissions';

const valid: AdminPermission = {
  id: 'widgets.read',
  class: 'read',
  resource: 'widgets',
  description: 'Read the widgets.',
};

describe('the admin permission catalog (#507)', () => {
  it('holds the permissions the first operations need, each with its class', () => {
    expect(
      ADMIN_PERMISSIONS.map(({ id, class: permissionClass }) => [id, permissionClass])
    ).toEqual([
      ['realms.read', 'read'],
      ['realms.export', 'read'],
      ['realms.import.plan', 'read'],
      ['realms.policies.write', 'write'],
      ['realms.policies.security', 'security'],
      ['plugins.read', 'read'],
      ['plugins.security', 'security'],
      ['approvals.read', 'read'],
      ['approvals.approve', 'security'],
    ]);
  });

  it('gives each security permission an id no write permission has', () => {
    const security = PERMISSION_REGISTRY.ofClass('security').map((permission) => permission.id);
    const write = PERMISSION_REGISTRY.ofClass('write').map((permission) => permission.id);
    expect(security).toEqual(['realms.policies.security', 'plugins.security', 'approvals.approve']);
    expect(security.filter((id) => write.includes(id))).toEqual([]);
  });

  it('retires nothing yet', () => {
    expect(PERMISSION_REGISTRY.active).toEqual(PERMISSION_REGISTRY.all);
  });

  it('cannot be changed at run time', () => {
    expect(Object.isFrozen(ADMIN_PERMISSIONS)).toBe(true);
    expect(Object.isFrozen(PERMISSION_REGISTRY.all)).toBe(true);
    for (const permission of PERMISSION_REGISTRY.all)
      expect(Object.isFrozen(permission)).toBe(true);
    expect(() => {
      (PERMISSION_REGISTRY.all as AdminPermission[]).push(valid);
    }).toThrow(TypeError);
  });
});

describe('createPermissionRegistry', () => {
  // Acceptance criterion of #507: two permissions cannot register with the same id.
  it('refuses two permissions with the same id', () => {
    expect(() =>
      createPermissionRegistry([
        definePermission(valid),
        definePermission({ ...valid, description: 'Another meaning.' }),
      ])
    ).toThrow(
      new PermissionDefinitionError(
        'permission "widgets.read" is defined twice; an id names one permission'
      )
    );
  });

  it('refuses a retired permission and a new one with the same id: an id is never reused', () => {
    expect(() =>
      createPermissionRegistry([
        definePermission({ ...valid, retiredIn: 'v0.3.0' }),
        definePermission(valid),
      ])
    ).toThrow(PermissionDefinitionError);
  });

  it('refuses two ids that differ only in case', () => {
    expect(() =>
      createPermissionRegistry([
        definePermission({ ...valid, id: 'widgets.bulkRead', description: 'Read in bulk.' }),
        definePermission({ ...valid, id: 'widgets.bulkread', description: 'Read in bulk.' }),
      ])
    ).toThrow(/differ only in case/);
  });

  it('checks entries that did not come through definePermission', () => {
    expect(() => createPermissionRegistry([{ ...valid, class: 'admin' as never }])).toThrow(
      PermissionDefinitionError
    );
  });

  it('looks a permission up by its exact id', () => {
    const registry = createPermissionRegistry([definePermission(valid)]);
    expect(registry.get('widgets.read')).toEqual(valid);
    expect(registry.get('Widgets.read')).toBeUndefined();
    expect(registry.get('widgets')).toBeUndefined();
  });

  it('keeps a retired permission known but not grantable, and out of its class', () => {
    const registry = createPermissionRegistry([
      definePermission(valid),
      definePermission({
        id: 'widgets.list',
        class: 'read',
        resource: 'widgets',
        description: 'List the widgets.',
        retiredIn: 'v0.3.0',
      }),
    ]);
    expect(registry.get('widgets.list')?.retiredIn).toBe('v0.3.0');
    expect(registry.isGrantable('widgets.list')).toBe(false);
    expect(registry.isGrantable('widgets.read')).toBe(true);
    expect(registry.isGrantable('widgets.unknown')).toBe(false);
    expect(registry.all.map((permission) => permission.id)).toEqual([
      'widgets.read',
      'widgets.list',
    ]);
    expect(registry.active.map((permission) => permission.id)).toEqual(['widgets.read']);
    expect(registry.ofClass('read').map((permission) => permission.id)).toEqual(['widgets.read']);
  });
});

describe('definePermission', () => {
  it('returns a frozen copy of a well-formed entry', () => {
    const permission = definePermission(valid);
    expect(permission).toEqual(valid);
    expect(permission).not.toBe(valid);
    expect(Object.isFrozen(permission)).toBe(true);
  });

  it.each([
    'realms.read',
    'realms.policies.write',
    'realms.import.plan',
    'serviceAccounts.keys.rotate',
  ])('accepts the id %s', (id) => {
    expect(PERMISSION_ID_PATTERN.test(id)).toBe(true);
  });

  it.each([
    'realms',
    'Realms.read',
    'realms.Read',
    'realms..read',
    'realms.read.',
    'realms_read',
    'realms.policies-write',
    '',
  ])('refuses the id %j', (id) => {
    expect(PERMISSION_ID_PATTERN.test(id)).toBe(false);
    expect(() => definePermission({ ...valid, id, resource: id.split('.')[0] || 'x' })).toThrow(
      PermissionDefinitionError
    );
  });

  it('refuses a class other than read, write or security', () => {
    expect(() => definePermission({ ...valid, class: 'admin' as never })).toThrow(
      /class must be one of read, write, security/
    );
  });

  it('refuses a resource that is not the leading segments of the id', () => {
    expect(() => definePermission({ ...valid, resource: 'gadgets' })).toThrow(/resource/);
    expect(() => definePermission({ ...valid, resource: 'widgets.read' })).toThrow(/resource/);
    expect(() => definePermission({ ...valid, resource: 'widg' })).toThrow(/resource/);
    expect(
      definePermission({ ...valid, id: 'widgets.parts.read', resource: 'widgets.parts' }).resource
    ).toBe('widgets.parts');
  });

  it('refuses an id that names another class than its own', () => {
    expect(() => definePermission({ ...valid, id: 'widgets.security', class: 'write' })).toThrow(
      /ends in \.security must have the class security/
    );
    expect(() => definePermission({ ...valid, id: 'widgets.write', class: 'security' })).toThrow(
      PermissionDefinitionError
    );
    expect(definePermission({ ...valid, id: 'widgets.approve', class: 'security' }).class).toBe(
      'security'
    );
  });

  it.each(['', ' Read the widgets.', 'Read the widgets. ', 'Read\nthe widgets.'])(
    'refuses the description %j',
    (description) => {
      expect(() => definePermission({ ...valid, description })).toThrow(/description/);
    }
  );

  it('refuses a retiring release that is not a release tag', () => {
    expect(() => definePermission({ ...valid, retiredIn: '0.3.0' as never })).toThrow(/retiredIn/);
    expect(definePermission({ ...valid, retiredIn: 'v1.2.3' }).retiredIn).toBe('v1.2.3');
  });
});
