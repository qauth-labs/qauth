import { describe, expect, it } from 'vitest';

import { API_FAMILY_PREFIXES, apiFamilyOf, isUnversionedFamilyPath } from './families';

describe('API_FAMILY_PREFIXES', () => {
  it('serves every family under a release candidate until 1.0.0 (ADR-018 §5)', () => {
    expect(Object.values(API_FAMILY_PREFIXES)).toEqual([
      '/admin/v1-rc.0',
      '/account/v1-rc.0',
      '/developer/v1-rc.0',
    ]);
  });
});

describe('apiFamilyOf', () => {
  it.each([
    ['/admin/v1-rc.0/realms/:realmId', { family: 'admin', major: 1, rc: 0 }],
    ['/account/v1-rc.12', { family: 'account', major: 1, rc: 12 }],
    ['/developer/v1-rc.0/clients/{clientId}', { family: 'developer', major: 1, rc: 0 }],
    ['/admin/v1/realms', { family: 'admin', major: 1 }],
    ['/admin/v2/realms', { family: 'admin', major: 2 }],
  ])('reads %s', (path, expected) => {
    expect(apiFamilyOf(path)).toEqual(expected);
  });

  it.each([
    '/oauth/token',
    '/admin/realms',
    '/admin/v1-rc/realms',
    '/admin/v1-rc.01/realms',
    '/admin/v1-beta.0/realms',
    '/admin/v0/realms',
    '/administrators/v1-rc.0',
  ])('leaves %s outside the families', (path) => {
    expect(apiFamilyOf(path)).toBeUndefined();
  });
});

describe('isUnversionedFamilyPath', () => {
  it.each(['/admin/realms', '/admin/v1-rc/realms', '/account', '/developer/v1-beta.0'])(
    'flags %s',
    (path) => {
      expect(isUnversionedFamilyPath(path)).toBe(true);
    }
  );

  it.each(['/admin/v1-rc.0/realms', '/admin/v1/realms', '/oauth/token'])('accepts %s', (path) => {
    expect(isUnversionedFamilyPath(path)).toBe(false);
  });
});
