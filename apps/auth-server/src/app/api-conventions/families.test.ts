import {
  isReservedAudience,
  isReservedQauthScope,
  RESERVED_AUDIENCE_PREFIX,
} from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import {
  API_FAMILY_AUDIENCES,
  API_FAMILY_PREFIXES,
  API_FAMILY_SCOPES,
  apiFamilyOf,
  familyScopeOf,
  isUnversionedFamilyPath,
} from './families';

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

describe('API_FAMILY_AUDIENCES (#509)', () => {
  it('gives each family its own audience, versioned like its path (ADR-018 §5)', () => {
    expect(API_FAMILY_AUDIENCES).toEqual({
      admin: 'urn:qauth:aud:admin:v1-rc.0',
      account: 'urn:qauth:aud:account:v1-rc.0',
      developer: 'urn:qauth:aud:developer:v1-rc.0',
    });
    for (const [family, audience] of Object.entries(API_FAMILY_AUDIENCES)) {
      const prefix = API_FAMILY_PREFIXES[family as keyof typeof API_FAMILY_PREFIXES];
      expect(audience).toBe(`${RESERVED_AUDIENCE_PREFIX}${prefix.slice(1).replace('/', ':')}`);
      expect(isReservedAudience(audience)).toBe(true);
    }
  });
});

describe('API_FAMILY_SCOPES (#933)', () => {
  it('gives the account and developer families a read and a write scope each', () => {
    expect(API_FAMILY_SCOPES).toEqual({
      account: { read: 'qauth:account:read', write: 'qauth:account:write' },
      developer: { read: 'qauth:developer:read', write: 'qauth:developer:write' },
    });
  });

  it("puts every one in QAuth's reserved scope namespace", () => {
    for (const scopes of Object.values(API_FAMILY_SCOPES)) {
      for (const scope of Object.values(scopes)) expect(isReservedQauthScope(scope)).toBe(true);
    }
  });

  it('reads each scope back as its family and class', () => {
    expect(familyScopeOf('qauth:developer:write')).toEqual({
      family: 'developer',
      operationClass: 'write',
    });
    expect(familyScopeOf('qauth:account:read')).toEqual({
      family: 'account',
      operationClass: 'read',
    });
  });

  it.each([
    'qauth:admin:read',
    'QAuth:developer:read',
    'qauth:developer:read ',
    'qauth:developer:security',
    'developer:read',
  ])('reads %j as no family scope', (scope) => {
    expect(familyScopeOf(scope)).toBeUndefined();
  });
});
