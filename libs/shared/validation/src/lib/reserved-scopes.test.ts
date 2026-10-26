import { describe, expect, it } from 'vitest';

import {
  isReservedQauthScope,
  QAUTH_SCOPE_NAMESPACE,
  reservedQauthScopesIn,
} from './reserved-scopes';

describe('the reserved qauth: scope namespace (#507)', () => {
  it('is qauth:', () => {
    expect(QAUTH_SCOPE_NAMESPACE).toBe('qauth:');
  });

  it.each([
    'qauth:admin:read',
    'qauth:admin:write',
    'qauth:admin:security',
    'qauth:',
    'qauth:anything.else',
  ])('reserves %s', (scope) => {
    expect(isReservedQauthScope(scope)).toBe(true);
  });

  it.each(['QAuth:admin:read', 'QAUTH:ADMIN:SECURITY', 'qAuTh:admin:write'])(
    'reserves %s, whatever the case of the namespace',
    (scope) => {
      expect(isReservedQauthScope(scope)).toBe(true);
    }
  );

  it.each([
    // Other servers' scopes that look administrative are ordinary scopes.
    'admin:read',
    'admin:org',
    'Admin:Security',
    'qauth',
    'qauthx:read',
    'q:auth:read',
    'agent:admin',
    'example:qauth:read',
    ' qauth:admin:read',
    'openid',
    '',
    // Not ASCII, so no scope (RFC 6749 §3.3), and not folded onto ASCII: a
    // Cyrillic a, and fullwidth letters that only NFKC would make ASCII.
    'qаuth:admin:read',
    'ｑａｕｔｈ:admin:read',
  ])('leaves %j alone', (scope) => {
    expect(isReservedQauthScope(scope)).toBe(false);
  });

  it('picks the reserved entries out of a list, in order', () => {
    expect(
      reservedQauthScopesIn(['openid', 'qauth:admin:write', 'admin:org', 'QAUTH:admin:read'])
    ).toEqual(['qauth:admin:write', 'QAUTH:admin:read']);
    expect(reservedQauthScopesIn(new Set(['openid', 'admin:read']))).toEqual([]);
  });
});
