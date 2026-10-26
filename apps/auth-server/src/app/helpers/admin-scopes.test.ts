import { describe, expect, it } from 'vitest';

import {
  ADMIN_SCOPE_LIST,
  ADMIN_SCOPES,
  allowedPermissionClasses,
  isReservedQauthScope,
  PERMISSION_CLASSES,
  permissionClassOfScope,
  tokenScopeSet,
} from './admin-scopes';
import { AGENT_MODE_SCOPES } from './scope-modes';

describe('admin scopes (#507)', () => {
  it('are qauth:admin:read, qauth:admin:write and qauth:admin:security, one per permission class', () => {
    expect(PERMISSION_CLASSES).toEqual(['read', 'write', 'security']);
    expect(ADMIN_SCOPES).toEqual({
      read: 'qauth:admin:read',
      write: 'qauth:admin:write',
      security: 'qauth:admin:security',
    });
    expect(ADMIN_SCOPE_LIST).toEqual([
      'qauth:admin:read',
      'qauth:admin:write',
      'qauth:admin:security',
    ]);
  });

  it('each sit in the reserved qauth: namespace', () => {
    for (const scope of ADMIN_SCOPE_LIST) expect(isReservedQauthScope(scope)).toBe(true);
  });

  it('are not the admin: scopes of other servers', () => {
    for (const scope of ['admin:read', 'admin:write', 'admin:security', 'admin:org']) {
      expect(isReservedQauthScope(scope)).toBe(false);
      expect(permissionClassOfScope(scope)).toBeUndefined();
    }
  });

  it('do not collide with the reserved agent scope modes', () => {
    for (const scope of Object.values(AGENT_MODE_SCOPES)) {
      expect(isReservedQauthScope(scope)).toBe(false);
      expect(permissionClassOfScope(scope)).toBeUndefined();
    }
  });

  it('cannot be changed at run time', () => {
    expect(Object.isFrozen(ADMIN_SCOPES)).toBe(true);
    expect(Object.isFrozen(ADMIN_SCOPE_LIST)).toBe(true);
    expect(Object.isFrozen(PERMISSION_CLASSES)).toBe(true);
  });
});

describe('permissionClassOfScope', () => {
  it('maps each admin scope to its class', () => {
    expect(permissionClassOfScope('qauth:admin:read')).toBe('read');
    expect(permissionClassOfScope('qauth:admin:write')).toBe('write');
    expect(permissionClassOfScope('qauth:admin:security')).toBe('security');
  });

  it.each([
    'QAuth:admin:read',
    'qauth:ADMIN:SECURITY',
    'qauth:admin:read ',
    'admin:read',
    'qauth:admin:',
    'qauth:admin:admin',
    'qauth:',
    '',
  ])('allows nothing for %j: scopes match exactly (RFC 6749 §3.3)', (scope) => {
    expect(permissionClassOfScope(scope)).toBeUndefined();
  });
});

describe('allowedPermissionClasses — the scopes are independent', () => {
  it('qauth:admin:write allows write and nothing else: not read, not security', () => {
    expect([...allowedPermissionClasses(['qauth:admin:write'])]).toEqual(['write']);
  });

  it('qauth:admin:security allows security and nothing else: not read, not write', () => {
    expect([...allowedPermissionClasses(['qauth:admin:security'])]).toEqual(['security']);
  });

  it('qauth:admin:read allows read and nothing else', () => {
    expect([...allowedPermissionClasses(['qauth:admin:read'])]).toEqual(['read']);
  });

  it('allows each class whose scope is present, and only those', () => {
    expect(allowedPermissionClasses('qauth:admin:write qauth:admin:security')).toEqual(
      new Set(['write', 'security'])
    );
    expect(allowedPermissionClasses('openid profile agent:admin')).toEqual(new Set());
  });
});

describe('tokenScopeSet', () => {
  it('splits the space-delimited scope claim', () => {
    expect(tokenScopeSet('openid  qauth:admin:read')).toEqual(
      new Set(['openid', 'qauth:admin:read'])
    );
    expect(tokenScopeSet('')).toEqual(new Set());
  });

  it('takes a list as it is, never a string as its characters', () => {
    expect(tokenScopeSet(['qauth:admin:read', 'qauth:admin:read'])).toEqual(
      new Set(['qauth:admin:read'])
    );
    expect(tokenScopeSet('qauth:admin:read')).toEqual(new Set(['qauth:admin:read']));
  });
});
