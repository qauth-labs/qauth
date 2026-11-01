import { describe, expect, it, vi } from 'vitest';

vi.mock('../../config/env', () => ({
  env: {
    DYNAMIC_CLIENT_BADGE_DAYS: 30,
  },
}));

import {
  administrativeConsentFor,
  administrativeConsentScopes,
  agentPersistenceLine,
  canSkipConsent,
  describeDuration,
  describeScope,
  filterRequestedScopes,
  forcesLoginPrompt,
  isDynamicClientWithinBadgeWindow,
  isScopeSubset,
  type OAuthClientLike,
  type OAuthConsentLike,
} from './consent';

function client(overrides: Partial<OAuthClientLike> = {}): OAuthClientLike {
  return {
    scopes: ['read:foo', 'write:foo', 'email'],
    dynamicRegisteredAt: null,
    isAgent: false,
    firstPartyProfile: null,
    firstPartyPolicy: null,
    tokenEndpointAuthMethod: 'client_secret_basic',
    grantTypes: ['authorization_code', 'refresh_token'],
    developerId: null,
    metadata: null,
    ...overrides,
  };
}

/** An operator-flagged `web_redirect` client, such as the portal (ADR-017 Decision 2). */
function webRedirect(overrides: Partial<OAuthClientLike> = {}): OAuthClientLike {
  return client({
    firstPartyProfile: 'web_redirect',
    tokenEndpointAuthMethod: 'private_key_jwt',
    ...overrides,
  });
}

/** An operator-flagged `native_backend` client with the default policy. */
function nativeBackend(overrides: Partial<OAuthClientLike> = {}): OAuthClientLike {
  return client({
    firstPartyProfile: 'native_backend',
    firstPartyPolicy: { flows: ['login'] },
    tokenEndpointAuthMethod: 'private_key_jwt',
    ...overrides,
  });
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

// ADR-017 Decision 9 (#633): the administrative consent of an operator-flagged
// first-party client.
describe('administrativeConsentFor', () => {
  it('covers a web_redirect client asking for no dangerous scope, with its profile as the basis', () => {
    expect(administrativeConsentFor(webRedirect(), ['read:foo', 'email'])).toEqual({
      basis: 'web_redirect',
      scopes: ['read:foo', 'email'],
    });
  });

  it('covers a native_backend client whose policy parses', () => {
    expect(administrativeConsentFor(nativeBackend(), ['email'])).toEqual({
      basis: 'native_backend',
      scopes: ['email'],
    });
  });

  it('covers an empty scope set: the request asks for nothing to consent to', () => {
    expect(administrativeConsentFor(webRedirect(), [])).toEqual({
      basis: 'web_redirect',
      scopes: [],
    });
  });

  it('never covers a request with a dangerous scope, which shows the screen', () => {
    expect(administrativeConsentFor(webRedirect(), ['read:foo', 'write:foo'])).toBeNull();
    expect(
      administrativeConsentFor(webRedirect({ scopes: ['agent:exec'] }), ['agent:exec'])
    ).toBeNull();
    expect(administrativeConsentFor(nativeBackend(), ['email', 'write:foo'])).toBeNull();
  });

  it('is null for a client without a profile: nothing else widens the waiver', () => {
    expect(administrativeConsentFor(client(), ['email'])).toBeNull();
    expect(
      administrativeConsentFor(client({ tokenEndpointAuthMethod: 'private_key_jwt' }), ['email'])
    ).toBeNull();
  });

  it('is null when the profile does not resolve (fail-closed resolver)', () => {
    // Each row breaks one rule the database CHECKs hold, or carries a policy
    // that does not parse: the resolver reads it as no profile.
    for (const row of [
      webRedirect({ tokenEndpointAuthMethod: 'client_secret_basic' }),
      webRedirect({ developerId: '00000000-0000-4000-8000-000000000001' }),
      webRedirect({ isAgent: true }),
      webRedirect({ dynamicRegisteredAt: Date.now() }),
      webRedirect({ metadata: { registrationType: 'cimd' } }),
      webRedirect({ firstPartyPolicy: { flows: ['login'] } }),
      webRedirect({ firstPartyProfile: 'native_attested' }),
      nativeBackend({ firstPartyPolicy: null }),
      nativeBackend({ firstPartyPolicy: { flows: ['login'], unknown: true } }),
      nativeBackend({ grantTypes: ['refresh_token'] }),
    ]) {
      expect(administrativeConsentFor(row, ['email'])).toBeNull();
    }
  });
});

describe('administrativeConsentScopes', () => {
  it("is a first-party client's requested scopes minus the dangerous ones", () => {
    expect(administrativeConsentScopes(webRedirect(), ['read:foo', 'write:foo', 'email'])).toEqual([
      'read:foo',
      'email',
    ]);
    expect(administrativeConsentScopes(nativeBackend(), ['write:foo'])).toEqual([]);
  });

  it('is empty for a client whose profile does not resolve', () => {
    expect(administrativeConsentScopes(client(), ['read:foo', 'email'])).toEqual([]);
    expect(
      administrativeConsentScopes(webRedirect({ developerId: 'someone' }), ['read:foo'])
    ).toEqual([]);
  });
});

describe('forcesLoginPrompt', () => {
  it('holds for a native_backend client only', () => {
    expect(forcesLoginPrompt(nativeBackend())).toBe(true);
    expect(forcesLoginPrompt(webRedirect())).toBe(false);
    expect(forcesLoginPrompt(client())).toBe(false);
  });

  it('does not hold for a native_backend row the resolver refuses', () => {
    expect(forcesLoginPrompt(nativeBackend({ tokenEndpointAuthMethod: 'none' }))).toBe(false);
    expect(forcesLoginPrompt(nativeBackend({ firstPartyPolicy: { flows: [] } }))).toBe(false);
  });
});

describe('canSkipConsent with an administrative consent (ADR-017 Decision 9)', () => {
  it('skips the screen for a first-party client with no stored consent', () => {
    expect(canSkipConsent(undefined, webRedirect(), ['read:foo', 'email'], [])).toBe(true);
    expect(canSkipConsent(undefined, nativeBackend(), ['email'], [])).toBe(true);
  });

  it('skips it whatever the stored consent says, revoked or narrower', () => {
    const revoked = consent({ scopes: ['email'], revokedAt: Date.now() - 1000 });
    expect(canSkipConsent(revoked, webRedirect(), ['read:foo', 'email'], [])).toBe(true);
  });

  it('covers the resources of the request without a stored grant for them', () => {
    expect(canSkipConsent(undefined, webRedirect(), ['email'], ['https://rs.example/'])).toBe(true);
  });

  it('does not skip a dangerous scope without a stored consent', () => {
    expect(canSkipConsent(undefined, webRedirect(), ['read:foo', 'write:foo'], [])).toBe(false);
  });

  it('leaves clients without a profile to the stored consent alone', () => {
    expect(canSkipConsent(undefined, client(), ['email'], [])).toBe(false);
    expect(
      canSkipConsent(undefined, client({ tokenEndpointAuthMethod: 'private_key_jwt' }), [], [])
    ).toBe(false);
    expect(canSkipConsent(consent({ scopes: ['email'] }), client(), ['email'], [])).toBe(true);
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

describe('describeScope', () => {
  it('returns mapped description when known', () => {
    expect(describeScope('openid')).toContain('identity');
    expect(describeScope('email')).toContain('email');
  });

  it('falls back to raw scope', () => {
    expect(describeScope('write:widgets')).toBe('write:widgets');
  });
});
