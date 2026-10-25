import { describe, expect, it } from 'vitest';

import {
  API_FAMILY_AUDIENCES,
  API_FAMILY_PREFIXES,
  apiFamilyOf,
  isReservedAudience,
  isUnversionedFamilyPath,
  RESERVED_AUDIENCE_PREFIX,
  reservedAudiencesIn,
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

describe('the reserved urn:qauth:aud: namespace (#509)', () => {
  it.each([
    'urn:qauth:aud:admin:v1-rc.0',
    'urn:qauth:aud:other',
    'URN:QAuth:AUD:developer:v1-rc.0',
    '  urn:qauth:aud:account:v1-rc.0',
  ])('reserves %j', (value) => {
    expect(isReservedAudience(value)).toBe(true);
  });

  it.each([
    'https://api.example.com',
    'urn:qauth:audience',
    'urn:qauth:event:user.signed_in:v1-rc.0',
    'urn:example:aud:admin',
    'x-urn:qauth:aud:admin',
  ])('leaves %j to its owner', (value) => {
    expect(isReservedAudience(value)).toBe(false);
  });

  it('finds the reserved entries of a string or a list, and ignores other shapes', () => {
    expect(reservedAudiencesIn('urn:qauth:aud:admin:v1-rc.0')).toEqual([
      'urn:qauth:aud:admin:v1-rc.0',
    ]);
    expect(
      reservedAudiencesIn(['https://api.example.com', 'urn:qauth:aud:account:v1-rc.0', 7])
    ).toEqual(['urn:qauth:aud:account:v1-rc.0']);
    for (const value of [undefined, null, 42, { aud: 'urn:qauth:aud:admin:v1-rc.0' }, []]) {
      expect(reservedAudiencesIn(value)).toEqual([]);
    }
  });
});
