import { describe, expect, it } from 'vitest';

import { InvalidRealmHostError } from './realm-host';
import { expectedOrigin, RealmWithoutIssuerError, resolveRpId } from './realm-relying-party';

/** ADR-019 Decision 2: a realm's RP ID and origin, from its row (issue #553). */

describe('resolveRpId', () => {
  it('defaults to the primary host, the host of the issuer', () => {
    expect(resolveRpId({ issuer: 'https://auth.example.com', webauthnRpId: null })).toBe(
      'auth.example.com'
    );
  });

  it('never carries a port from the issuer', () => {
    for (const issuer of [
      'https://auth.example.com:8443',
      'https://auth.example.com:443',
      'https://auth.example.com:8443/tenant',
    ]) {
      expect(resolveRpId({ issuer, webauthnRpId: null })).toBe('auth.example.com');
    }
    expect(resolveRpId({ issuer: 'http://auth.localhost:3000', webauthnRpId: null })).toBe(
      'auth.localhost'
    );
  });

  it('returns the stored RP ID when the operator set one', () => {
    expect(resolveRpId({ issuer: 'https://auth.example.com', webauthnRpId: 'example.com' })).toBe(
      'example.com'
    );
  });

  it('gives the host form of the issuer host: lower case, punycode', () => {
    expect(resolveRpId({ issuer: 'https://AUTH.Example.COM', webauthnRpId: null })).toBe(
      'auth.example.com'
    );
    expect(resolveRpId({ issuer: 'https://auth.bücher.example', webauthnRpId: null })).toBe(
      'auth.xn--bcher-kva.example'
    );
  });

  it('refuses a realm without an issuer, which has no host yet', () => {
    expect(() => resolveRpId({ issuer: null, webauthnRpId: null })).toThrow(
      RealmWithoutIssuerError
    );
    expect(resolveRpId({ issuer: null, webauthnRpId: 'example.com' })).toBe('example.com');
  });

  it('refuses an IP address, which WebAuthn does not accept as an RP ID', () => {
    expect(() => resolveRpId({ issuer: 'https://192.0.2.1', webauthnRpId: null })).toThrow(
      InvalidRealmHostError
    );
  });
});

describe('expectedOrigin', () => {
  it("is the issuer's origin, port included, path dropped", () => {
    expect(expectedOrigin({ issuer: 'https://auth.example.com' })).toBe('https://auth.example.com');
    expect(expectedOrigin({ issuer: 'https://auth.example.com:8443/tenant' })).toBe(
      'https://auth.example.com:8443'
    );
    expect(expectedOrigin({ issuer: 'http://localhost:3000' })).toBe('http://localhost:3000');
  });

  it('is the form a browser writes: lower case, default port dropped', () => {
    expect(expectedOrigin({ issuer: 'https://Auth.Example.com:443' })).toBe(
      'https://auth.example.com'
    );
  });

  it('refuses a realm without an issuer', () => {
    expect(() => expectedOrigin({ issuer: null })).toThrow(RealmWithoutIssuerError);
  });
});
