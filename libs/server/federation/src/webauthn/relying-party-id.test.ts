import { describe, expect, it } from 'vitest';

import {
  assertRelyingPartyIdUnlockedOrSame,
  parentDomainRpIdWarning,
  RelyingPartyIdError,
  type RelyingPartyIdErrorReason,
  RelyingPartyIdLockedError,
  type RelyingPartyIdSettings,
  resolveRelyingPartyId,
} from './relying-party-id';

/** ADR-019 Decision 2: the RP ID rules (issue #467). */

const REALM_HOST = 'auth.example.com';

function reasonFor(settings: Partial<RelyingPartyIdSettings>): RelyingPartyIdErrorReason {
  try {
    resolveRelyingPartyId({ realmHost: REALM_HOST, allowParentDomain: false, ...settings });
  } catch (error) {
    expect(error).toBeInstanceOf(RelyingPartyIdError);
    return (error as RelyingPartyIdError).reason;
  }
  throw new Error('expected a refusal');
}

describe('resolveRelyingPartyId', () => {
  it("defaults to the realm's exact host", () => {
    for (const configured of [undefined, '', '  ']) {
      expect(
        resolveRelyingPartyId({ realmHost: REALM_HOST, configured, allowParentDomain: false })
      ).toEqual({ rpId: REALM_HOST, scope: 'realm-host' });
    }
  });

  it('accepts the realm host spelled any way a host may be', () => {
    expect(
      resolveRelyingPartyId({
        realmHost: REALM_HOST,
        configured: 'AUTH.Example.com.',
        allowParentDomain: false,
      })
    ).toEqual({ rpId: REALM_HOST, scope: 'realm-host' });
  });

  it('refuses a parent domain without the opt-in, saying what it would allow', () => {
    expect(reasonFor({ configured: 'example.com' })).toBe('parent-not-allowed');
    expect(() =>
      resolveRelyingPartyId({
        realmHost: REALM_HOST,
        configured: 'example.com',
        allowParentDomain: false,
      })
    ).toThrow('every host under "example.com" ask for assertions');
  });

  it('accepts a parent domain with the opt-in, and warns', () => {
    const resolved = resolveRelyingPartyId({
      realmHost: REALM_HOST,
      configured: 'example.com',
      allowParentDomain: true,
    });
    expect(resolved).toEqual({ rpId: 'example.com', scope: 'parent-domain' });
    expect(parentDomainRpIdWarning(resolved, REALM_HOST)).toContain(
      'every host under "example.com" can ask for assertions'
    );
    expect(parentDomainRpIdWarning({ rpId: REALM_HOST, scope: 'realm-host' }, REALM_HOST)).toBe(
      undefined
    );
  });

  it('refuses a host that is neither the realm host nor a parent of it', () => {
    expect(reasonFor({ configured: 'login.example.com' })).toBe('unrelated');
    expect(reasonFor({ configured: 'sub.auth.example.com', allowParentDomain: true })).toBe(
      'unrelated'
    );
    expect(reasonFor({ configured: 'badexample.com', allowParentDomain: true })).toBe('unrelated');
  });

  it('refuses a top-level domain even with the opt-in, but keeps localhost for development', () => {
    expect(reasonFor({ configured: 'com', allowParentDomain: true })).toBe('top-level');
    expect(
      resolveRelyingPartyId({
        realmHost: 'auth.localhost',
        configured: 'localhost',
        allowParentDomain: true,
      })
    ).toEqual({ rpId: 'localhost', scope: 'parent-domain' });
  });

  it('refuses what is not a host name, and an IP address', () => {
    expect(reasonFor({ configured: 'https://auth.example.com' })).toBe('not-a-host');
    expect(reasonFor({ configured: '192.0.2.1' })).toBe('not-a-host');
    expect(reasonFor({ configured: '*.example.com' })).toBe('not-a-host');
  });
});

describe('assertRelyingPartyIdUnlockedOrSame', () => {
  it('passes while the realm has no passkey, and when the RP ID is the locked one', () => {
    expect(() =>
      assertRelyingPartyIdUnlockedOrSame(null, { rpId: 'example.com', scope: 'parent-domain' })
    ).not.toThrow();
    expect(() =>
      assertRelyingPartyIdUnlockedOrSame(REALM_HOST, { rpId: REALM_HOST, scope: 'realm-host' })
    ).not.toThrow();
  });

  it('refuses another RP ID once a passkey is enrolled, naming both and the consequence', () => {
    const attempt = () =>
      assertRelyingPartyIdUnlockedOrSame(REALM_HOST, {
        rpId: 'example.com',
        scope: 'parent-domain',
      });
    expect(attempt).toThrow(RelyingPartyIdLockedError);
    expect(attempt).toThrow(
      'The realm\'s passkeys are bound to the RP ID "auth.example.com", but the configured RP ID is "example.com".'
    );
    expect(attempt).toThrow('would orphan every passkey');
  });
});
