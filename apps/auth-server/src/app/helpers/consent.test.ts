import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import {
  canSkipConsent,
  describeScope,
  filterRequestedScopes,
  isDynamicClientWithinBadgeWindow,
  isScopeSubset,
  type OAuthClientLike,
  type OAuthConsentLike,
} from './consent';

function client(overrides: Partial<OAuthClientLike> = {}): OAuthClientLike {
  return {
    scopes: ['read:foo', 'write:foo', 'email'],
    dynamicRegisteredAt: null,
    ...overrides,
  };
}

function consent(overrides: Partial<OAuthConsentLike> = {}): OAuthConsentLike {
  return {
    scopes: ['read:foo'],
    revokedAt: null,
    ...overrides,
  };
}

describe('isScopeSubset', () => {
  it('empty requested is always covered', () => {
    expect(isScopeSubset([], [])).toBe(true);
    expect(isScopeSubset([], ['read:foo'])).toBe(true);
  });

  it('exact match', () => {
    expect(isScopeSubset(['a', 'b'], ['a', 'b'])).toBe(true);
  });

  it('requested is proper subset of granted', () => {
    expect(isScopeSubset(['a'], ['a', 'b', 'c'])).toBe(true);
  });

  it('missing any scope fails', () => {
    expect(isScopeSubset(['a', 'x'], ['a', 'b'])).toBe(false);
  });
});

describe('filterRequestedScopes', () => {
  it('drops scopes not on the client allowlist', () => {
    expect(filterRequestedScopes('read:foo write:bar email', client())).toEqual([
      'read:foo',
      'email',
    ]);
  });

  it('de-duplicates and preserves request order', () => {
    expect(filterRequestedScopes('email read:foo email', client())).toEqual(['email', 'read:foo']);
  });

  it('handles missing scope parameter', () => {
    expect(filterRequestedScopes(undefined, client())).toEqual([]);
    expect(filterRequestedScopes('', client())).toEqual([]);
  });
});

describe('isDynamicClientWithinBadgeWindow', () => {
  it('null dynamicRegisteredAt is never new', () => {
    expect(isDynamicClientWithinBadgeWindow(client({ dynamicRegisteredAt: null }))).toBe(false);
  });

  it('recently registered is new', () => {
    expect(
      isDynamicClientWithinBadgeWindow(
        client({ dynamicRegisteredAt: Date.now() - 1 * 24 * 60 * 60 * 1000 })
      )
    ).toBe(true);
  });

  it('old registration is not new', () => {
    expect(
      isDynamicClientWithinBadgeWindow(
        client({ dynamicRegisteredAt: Date.now() - 365 * 24 * 60 * 60 * 1000 })
      )
    ).toBe(false);
  });
});

describe('canSkipConsent', () => {
  it('missing consent always requires prompt', () => {
    expect(canSkipConsent(undefined, client(), ['read:foo'])).toBe(false);
  });

  it('revoked consent requires prompt', () => {
    expect(canSkipConsent(consent({ revokedAt: Date.now() - 1000 }), client(), ['read:foo'])).toBe(
      false
    );
  });

  it('exceeded scopes require prompt', () => {
    expect(canSkipConsent(consent({ scopes: ['read:foo'] }), client(), ['write:foo'])).toBe(false);
  });

  it('subset scopes skip prompt', () => {
    expect(canSkipConsent(consent({ scopes: ['read:foo', 'email'] }), client(), ['email'])).toBe(
      true
    );
  });

  it('dynamic client inside badge window forces re-consent', () => {
    const c = client({ dynamicRegisteredAt: Date.now() - 1 * 24 * 60 * 60 * 1000 });
    expect(canSkipConsent(consent({ scopes: ['email'] }), c, ['email'])).toBe(false);
  });
});

describe('describeScope', () => {
  it('returns mapped description when known', () => {
    expect(describeScope('openid')).toContain('identity');
    expect(describeScope('email')).toContain('email');
  });

  it('falls back to raw scope', () => {
    expect(describeScope('write:widgets')).toBe('write:widgets');
  });
});
