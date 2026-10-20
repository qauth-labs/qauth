import { describe, expect, it } from 'vitest';

import { PROFILE_SCOPE, resolveDisplayName, resolveProfileClaimsForScopes } from './profile-claims';

const ADA = { firstName: 'Ada', lastName: 'Lovelace' };

describe('resolveDisplayName', () => {
  it.each([
    ['both parts', ADA, 'Ada Lovelace'],
    ['the first name only', { firstName: 'Ada', lastName: null }, 'Ada'],
    ['the last name only', { firstName: undefined, lastName: 'Lovelace' }, 'Lovelace'],
  ])('joins %s', (_label, user, expected) => {
    expect(resolveDisplayName(user)).toBe(expected);
  });

  it.each([
    ['both parts null', { firstName: null, lastName: null }],
    ['both parts absent', {}],
    ['both parts blank', { firstName: '  ', lastName: '' }],
  ])('returns undefined for %s, never an empty string', (_label, user) => {
    expect(resolveDisplayName(user)).toBeUndefined();
  });
});

describe('resolveProfileClaimsForScopes', () => {
  it('names the profile scope as OIDC Core §5.4 does', () => {
    expect(PROFILE_SCOPE).toBe('profile');
  });

  it('releases name when the profile scope was granted', () => {
    expect(resolveProfileClaimsForScopes(ADA, ['openid', 'profile'])).toEqual({
      name: 'Ada Lovelace',
    });
  });

  it('accepts any iterable of scopes, a Set included', () => {
    expect(resolveProfileClaimsForScopes(ADA, new Set(['profile']))).toEqual({
      name: 'Ada Lovelace',
    });
  });

  it.each([
    ['openid alone', ['openid']],
    ['openid email', ['openid', 'email']],
    ['no scope at all', []],
    // Scope tokens are case-sensitive (RFC 6749 §3.3).
    ['a differently cased scope', ['openid', 'Profile']],
  ])('releases nothing under %s, whatever the user has stored', (_label, scopes) => {
    const claims = resolveProfileClaimsForScopes(ADA, scopes);
    expect(claims).toEqual({});
    expect('name' in claims).toBe(false);
  });

  it('omits name under the profile scope when the user has none stored', () => {
    const claims = resolveProfileClaimsForScopes({ firstName: null, lastName: null }, ['profile']);
    expect(claims).toEqual({});
    // Absent, not undefined-valued: spreading the result must add no key.
    expect('name' in claims).toBe(false);
  });
});
