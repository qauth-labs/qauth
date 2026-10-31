import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import {
  agentPersistenceLine,
  canSkipConsent,
  describeDuration,
  describeScope,
  filterRequestedScopes,
  isDynamicClientWithinBadgeWindow,
  isLoopbackRedirect,
  isScopeSubset,
  type OAuthClientLike,
  type OAuthConsentLike,
} from './consent';

function client(overrides: Partial<OAuthClientLike> = {}): OAuthClientLike {
  return {
    scopes: ['read:foo', 'write:foo', 'email'],
    dynamicRegisteredAt: null,
    isAgent: false,
    ...overrides,
  };
}

function consent(overrides: Partial<OAuthConsentLike> = {}): OAuthConsentLike {
  return {
    scopes: ['read:foo'],
    resourceScopes: {},
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
    expect(canSkipConsent(undefined, client(), ['read:foo'], [])).toBe(false);
  });

  it('revoked consent requires prompt', () => {
    expect(
      canSkipConsent(consent({ revokedAt: Date.now() - 1000 }), client(), ['read:foo'], [])
    ).toBe(false);
  });

  it('exceeded scopes require prompt', () => {
    expect(canSkipConsent(consent({ scopes: ['read:foo'] }), client(), ['write:foo'], [])).toBe(
      false
    );
  });

  it('subset scopes skip prompt', () => {
    expect(
      canSkipConsent(consent({ scopes: ['read:foo', 'email'] }), client(), ['email'], [])
    ).toBe(true);
  });

  it('dynamic client inside badge window forces re-consent', () => {
    const c = client({ dynamicRegisteredAt: Date.now() - 1 * 24 * 60 * 60 * 1000 });
    expect(canSkipConsent(consent({ scopes: ['email'] }), c, ['email'], [])).toBe(false);
  });

  // RFC 8707: a `resource` becomes the token's `aud`. A remembered grant
  // covers the resource servers the user approved, not any the client names.
  const A = 'https://a.example/mcp';
  const B = 'https://b.example/mcp';

  it('scopes approved for every requested resource skip prompt', () => {
    const stored = consent({ resourceScopes: { [A]: ['read:foo'], [B]: ['read:foo'] } });
    expect(canSkipConsent(stored, client(), ['read:foo'], [B])).toBe(true);
    expect(canSkipConsent(stored, client(), ['read:foo'], [A, B])).toBe(true);
  });

  it('a resource the user never approved requires prompt, even with covered scopes', () => {
    const stored = consent({ resourceScopes: { [A]: ['read:foo'] } });
    expect(canSkipConsent(stored, client(), ['read:foo'], [B])).toBe(false);
    expect(canSkipConsent(stored, client(), ['read:foo'], [A, B])).toBe(false);
    // An empty scope set is a subset of anything; it still names the `aud`.
    expect(canSkipConsent(stored, client(), [], [B])).toBe(false);
    // A grant that recorded no resource covers none.
    expect(canSkipConsent(consent(), client(), ['read:foo'], [A])).toBe(false);
  });

  it('a scope approved for another resource only requires prompt', () => {
    const stored = consent({
      scopes: ['email', 'read:foo'],
      resourceScopes: { [A]: ['read:foo'], [B]: ['email'] },
    });
    expect(canSkipConsent(stored, client(), ['read:foo'], [B])).toBe(false);
  });

  it('matches a resource exactly, never through the prototype', () => {
    expect(canSkipConsent(consent(), client(), [], ['constructor'])).toBe(false);
  });

  // ADR-015 Decision 11 (#845): every authorization of an agent shows the
  // screen, which names it as an agent and says how long it may keep working.
  it('never skips the screen for an agent client, even under a covering consent', () => {
    const covering = consent({ scopes: ['read:foo', 'email'], resourceScopes: { [A]: ['email'] } });
    const agent = client({ isAgent: true });
    expect(canSkipConsent(covering, client(), ['email'], [])).toBe(true);
    expect(canSkipConsent(covering, agent, ['email'], [])).toBe(false);
    expect(canSkipConsent(covering, agent, [], [])).toBe(false);
    expect(canSkipConsent(covering, client(), ['email'], [A])).toBe(true);
    expect(canSkipConsent(covering, agent, ['email'], [A])).toBe(false);
  });
});

describe('describeDuration', () => {
  it('names a whole unit alone', () => {
    expect(describeDuration(1)).toBe('1 second');
    expect(describeDuration(60)).toBe('1 minute');
    expect(describeDuration(3600)).toBe('1 hour');
    expect(describeDuration(86_400)).toBe('1 day');
    expect(describeDuration(30 * 86_400)).toBe('30 days');
    expect(describeDuration(2 * 3600)).toBe('2 hours');
  });

  it('names every unit it holds, never rounding', () => {
    expect(describeDuration(90)).toBe('1 minute and 30 seconds');
    expect(describeDuration(90_000)).toBe('1 day and 1 hour');
    expect(describeDuration(90_061)).toBe('1 day, 1 hour, 1 minute and 1 second');
    expect(describeDuration(86_400 + 1)).toBe('1 day and 1 second');
    expect(describeDuration(7 * 86_400 + 12 * 3600)).toBe('7 days and 12 hours');
  });

  it('drops a fraction of a second', () => {
    expect(describeDuration(3600.9)).toBe('1 hour');
  });
});

describe('agentPersistenceLine', () => {
  it('says only "until you revoke it" without a realm limit', () => {
    expect(agentPersistenceLine(null)).toBe('It may keep working until you revoke it.');
  });

  it('names the realm limit as a duration from the sign-in when the realm sets one', () => {
    expect(agentPersistenceLine(86_400)).toBe(
      'It may keep working until you revoke it, or until 1 day after you signed in, ' +
        'whichever comes first.'
    );
    expect(agentPersistenceLine(5400)).toBe(
      'It may keep working until you revoke it, or until 1 hour and 30 minutes after you ' +
        'signed in, whichever comes first.'
    );
  });
});

describe('isLoopbackRedirect', () => {
  it('flags localhost and ::1', () => {
    expect(isLoopbackRedirect('http://localhost/cb')).toBe(true);
    expect(isLoopbackRedirect('http://localhost:8080/cb')).toBe(true);
    expect(isLoopbackRedirect('http://[::1]:5173/cb')).toBe(true); // URL strips brackets
  });

  it('flags 127.0.0.1', () => {
    expect(isLoopbackRedirect('http://127.0.0.1/cb')).toBe(true);
    expect(isLoopbackRedirect('http://127.0.0.1:3000/cb')).toBe(true);
  });

  // Regression: the entire 127.0.0.0/8 block loops back, not just 127.0.0.1.
  // A client could otherwise dodge the consent-screen warning via 127.0.0.2.
  it('flags the whole 127.0.0.0/8 loopback range', () => {
    expect(isLoopbackRedirect('http://127.0.0.2/cb')).toBe(true);
    expect(isLoopbackRedirect('http://127.1.2.3/cb')).toBe(true);
    expect(isLoopbackRedirect('http://127.255.255.254:9000/cb')).toBe(true);
  });

  it('does NOT flag genuine remote hosts', () => {
    expect(isLoopbackRedirect('https://app.example.com/cb')).toBe(false);
    expect(isLoopbackRedirect('https://12.7.0.0.1.example.com/cb')).toBe(false);
    expect(isLoopbackRedirect('https://128.0.0.1/cb')).toBe(false);
    expect(isLoopbackRedirect('https://1.2.3.4/cb')).toBe(false);
  });

  it('returns false for an unparseable redirect_uri', () => {
    expect(isLoopbackRedirect('not a url')).toBe(false);
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
