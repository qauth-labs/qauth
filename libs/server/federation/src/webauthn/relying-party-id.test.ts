import { describe, expect, it } from 'vitest';

import {
  assertRelyingPartyIdUnlockedOrSame,
  RelyingPartyIdError,
  type RelyingPartyIdErrorReason,
  RelyingPartyIdLockedError,
  type RelyingPartyIdSettings,
  resolveRelyingPartyId,
} from './relying-party-id';

/** ADR-019 Decision 2: the RP ID rules (issues #467 and #553). */

const REALM_HOST = 'auth.example.com';

function reasonFor(settings: Partial<RelyingPartyIdSettings>): RelyingPartyIdErrorReason {
  try {
    resolveRelyingPartyId({ realmHost: REALM_HOST, allowParentDomainRpId: false, ...settings });
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
        resolveRelyingPartyId({ realmHost: REALM_HOST, configured, allowParentDomainRpId: false })
      ).toEqual({ rpId: REALM_HOST, scope: 'realm-host', warning: undefined });
    }
  });

  it('accepts the realm host spelled any way a host may be', () => {
    expect(
      resolveRelyingPartyId({
        realmHost: REALM_HOST,
        configured: 'AUTH.Example.com.',
        allowParentDomainRpId: false,
      })
    ).toEqual({ rpId: REALM_HOST, scope: 'realm-host', warning: undefined });
  });

  it('never carries the port of a host:port value into the RP ID', () => {
    expect(
      resolveRelyingPartyId({
        realmHost: REALM_HOST,
        configured: 'auth.example.com:8443',
        allowParentDomainRpId: false,
      })
    ).toMatchObject({ rpId: REALM_HOST });
  });

  it('refuses a parent domain without the opt-in, saying what it would allow', () => {
    expect(reasonFor({ configured: 'example.com' })).toBe('parent-not-allowed');
    expect(() =>
      resolveRelyingPartyId({
        realmHost: REALM_HOST,
        configured: 'example.com',
        allowParentDomainRpId: false,
      })
    ).toThrow('every host under "example.com" ask for assertions');
  });

  it('accepts a parent domain with the opt-in, and returns a warning with it', () => {
    const resolved = resolveRelyingPartyId({
      realmHost: REALM_HOST,
      configured: 'example.com',
      allowParentDomainRpId: true,
    });
    expect(resolved).toMatchObject({ rpId: 'example.com', scope: 'parent-domain' });
    expect(resolved.warning).toContain('every host under "example.com" can ask for assertions');
  });

  it('accepts a deeper parent domain under a multi-label public suffix', () => {
    expect(
      resolveRelyingPartyId({
        realmHost: 'auth.id.example.co.uk',
        configured: 'example.co.uk',
        allowParentDomainRpId: true,
      })
    ).toMatchObject({ rpId: 'example.co.uk', scope: 'parent-domain' });
  });

  it('refuses a host that is not a parent of the realm host on a label boundary', () => {
    expect(reasonFor({ configured: 'login.example.com' })).toBe('unrelated');
    expect(reasonFor({ configured: 'evil.com', allowParentDomainRpId: true })).toBe('unrelated');
    expect(reasonFor({ configured: 'notexample.com', allowParentDomainRpId: true })).toBe(
      'unrelated'
    );
    expect(reasonFor({ configured: 'sub.auth.example.com', allowParentDomainRpId: true })).toBe(
      'unrelated'
    );
    expect(reasonFor({ configured: 'badexample.com', allowParentDomainRpId: true })).toBe(
      'unrelated'
    );
  });

  it('refuses a public suffix even with the opt-in, from the Public Suffix List', () => {
    expect(reasonFor({ configured: 'com', allowParentDomainRpId: true })).toBe('public-suffix');
    expect(reasonFor({ configured: 'com' })).toBe('public-suffix');
    // ICANN section, more than one label.
    expect(
      reasonFor({
        realmHost: 'auth.example.co.uk',
        configured: 'co.uk',
        allowParentDomainRpId: true,
      })
    ).toBe('public-suffix');
    // A wildcard rule of the list (`*.ck`).
    expect(
      reasonFor({
        realmHost: 'auth.example.ck',
        configured: 'example.ck',
        allowParentDomainRpId: true,
      })
    ).toBe('public-suffix');
    // A single label the list does not know falls under its default rule.
    expect(
      reasonFor({ realmHost: 'auth.internal', configured: 'internal', allowParentDomainRpId: true })
    ).toBe('public-suffix');
  });

  it('refuses a private-section public suffix, where a hosting provider hands out the names under it', () => {
    expect(
      reasonFor({
        realmHost: 'auth.tenant.appspot.com',
        configured: 'appspot.com',
        allowParentDomainRpId: true,
      })
    ).toBe('public-suffix');
  });

  it('keeps localhost as a parent domain, for development', () => {
    expect(
      resolveRelyingPartyId({
        realmHost: 'auth.localhost',
        configured: 'localhost',
        allowParentDomainRpId: true,
      })
    ).toMatchObject({ rpId: 'localhost', scope: 'parent-domain' });
  });

  it('refuses what is not a host name, and an IP address', () => {
    expect(reasonFor({ configured: 'https://auth.example.com' })).toBe('not-a-host');
    expect(reasonFor({ configured: '192.0.2.1' })).toBe('not-a-host');
    expect(reasonFor({ configured: '*.example.com' })).toBe('not-a-host');
  });
});

describe('assertRelyingPartyIdUnlockedOrSame', () => {
  it('passes while the realm has no passkey, and when the RP ID is the locked one', () => {
    expect(() => assertRelyingPartyIdUnlockedOrSame(null, { rpId: 'example.com' })).not.toThrow();
    expect(() =>
      assertRelyingPartyIdUnlockedOrSame(REALM_HOST, { rpId: REALM_HOST })
    ).not.toThrow();
  });

  it('refuses another RP ID once a passkey is enrolled, naming both and the consequence', () => {
    const attempt = () => assertRelyingPartyIdUnlockedOrSame(REALM_HOST, { rpId: 'example.com' });
    expect(attempt).toThrow(RelyingPartyIdLockedError);
    expect(attempt).toThrow(
      'The realm\'s passkeys are bound to the RP ID "auth.example.com", but the configured RP ID is "example.com".'
    );
    expect(attempt).toThrow('would orphan every passkey');
  });
});
