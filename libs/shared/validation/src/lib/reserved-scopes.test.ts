import { describe, expect, it } from 'vitest';

import {
  isReservedAdminScope,
  RESERVED_ADMIN_SCOPE_PREFIX,
  reservedAdminScopesIn,
} from './reserved-scopes';

describe('the reserved admin: scope prefix (#507)', () => {
  it('is admin:', () => {
    expect(RESERVED_ADMIN_SCOPE_PREFIX).toBe('admin:');
  });

  it.each(['admin:read', 'admin:write', 'admin:security', 'admin:', 'admin:anything.else'])(
    'reserves %s',
    (scope) => {
      expect(isReservedAdminScope(scope)).toBe(true);
    }
  );

  it.each(['Admin:read', 'ADMIN:SECURITY', 'aDmIn:write'])(
    'reserves %s, whatever the case of the prefix',
    (scope) => {
      expect(isReservedAdminScope(scope)).toBe(true);
    }
  );

  it.each([
    'admin',
    'administrator',
    'admins:read',
    'agent:admin',
    'example:admin',
    'realm:admin:read',
    ' admin:read',
    'openid',
    '',
    // Not ASCII, so no scope (RFC 6749 §3.3), and not folded onto ASCII.
    'ADM\u0130N:read',
    'adm\u0131n:read',
  ])('leaves %j alone', (scope) => {
    expect(isReservedAdminScope(scope)).toBe(false);
  });

  it('picks the reserved entries out of a list, in order', () => {
    expect(reservedAdminScopesIn(['openid', 'admin:write', 'profile', 'ADMIN:read'])).toEqual([
      'admin:write',
      'ADMIN:read',
    ]);
    expect(reservedAdminScopesIn(new Set(['openid', 'email']))).toEqual([]);
  });
});
