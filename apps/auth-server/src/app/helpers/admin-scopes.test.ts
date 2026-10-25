import { describe, expect, it } from 'vitest';

import {
  ADMIN_SCOPE_LIST,
  ADMIN_SCOPE_PREFIX,
  ADMIN_SCOPES,
  allowedPermissionClasses,
  isReservedAdminScope,
  PERMISSION_CLASSES,
  permissionClassOfScope,
  tokenScopeSet,
} from './admin-scopes';
import { AGENT_MODE_SCOPES } from './scope-modes';

describe('admin scopes (#507)', () => {
  it('are admin:read, admin:write and admin:security, one per permission class', () => {
    expect(PERMISSION_CLASSES).toEqual(['read', 'write', 'security']);
    expect(ADMIN_SCOPES).toEqual({
      read: 'admin:read',
      write: 'admin:write',
      security: 'admin:security',
    });
    expect(ADMIN_SCOPE_LIST).toEqual(['admin:read', 'admin:write', 'admin:security']);
  });

  it('each carry the reserved prefix', () => {
    expect(ADMIN_SCOPE_PREFIX).toBe('admin:');
    for (const scope of ADMIN_SCOPE_LIST) expect(isReservedAdminScope(scope)).toBe(true);
  });

  it('do not collide with the reserved agent scope modes', () => {
    for (const scope of Object.values(AGENT_MODE_SCOPES)) {
      expect(isReservedAdminScope(scope)).toBe(false);
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
    expect(permissionClassOfScope('admin:read')).toBe('read');
    expect(permissionClassOfScope('admin:write')).toBe('write');
    expect(permissionClassOfScope('admin:security')).toBe('security');
  });

  it.each(['Admin:read', 'ADMIN:SECURITY', 'admin:read ', 'admin:', 'admin:admin', 'admin', ''])(
    'allows nothing for %j: scopes match exactly (RFC 6749 §3.3)',
    (scope) => {
      expect(permissionClassOfScope(scope)).toBeUndefined();
    }
  );
});

describe('allowedPermissionClasses — the scopes are independent', () => {
  it('admin:write allows write and nothing else: not read, not security', () => {
    expect([...allowedPermissionClasses(['admin:write'])]).toEqual(['write']);
  });

  it('admin:security allows security and nothing else: not read, not write', () => {
    expect([...allowedPermissionClasses(['admin:security'])]).toEqual(['security']);
  });

  it('admin:read allows read and nothing else', () => {
    expect([...allowedPermissionClasses(['admin:read'])]).toEqual(['read']);
  });

  it('allows each class whose scope is present, and only those', () => {
    expect(allowedPermissionClasses('admin:write admin:security')).toEqual(
      new Set(['write', 'security'])
    );
    expect(allowedPermissionClasses('openid profile agent:admin')).toEqual(new Set());
  });
});

describe('tokenScopeSet', () => {
  it('splits the space-delimited scope claim', () => {
    expect(tokenScopeSet('openid  admin:read')).toEqual(new Set(['openid', 'admin:read']));
    expect(tokenScopeSet('')).toEqual(new Set());
  });

  it('takes a list as it is, never a string as its characters', () => {
    expect(tokenScopeSet(['admin:read', 'admin:read'])).toEqual(new Set(['admin:read']));
    expect(tokenScopeSet('admin:read')).toEqual(new Set(['admin:read']));
  });
});
