import { RealmWithoutIssuerError } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import {
  passkeyCeremonyOrigins,
  PasskeyRelyingPartyError,
  REALM_HOST_RELYING_PARTY,
  resolveRealmRelyingParty,
  servesAssociationFiles,
} from './webauthn-relying-party';

/** The default realm's passkey RP ID, worded for the operator (#467, #553). */
describe('resolveRealmRelyingParty', () => {
  it('is the realm host by default, and then the association files are served', () => {
    const relyingParty = resolveRealmRelyingParty('auth.example.com', REALM_HOST_RELYING_PARTY);
    expect(relyingParty).toEqual({
      rpId: 'auth.example.com',
      scope: 'realm-host',
      realmHost: 'auth.example.com',
      warning: undefined,
    });
    expect(servesAssociationFiles(relyingParty)).toBe(true);
  });

  it('is the realm host when WEBAUTHN_RP_ID names it', () => {
    expect(
      servesAssociationFiles(
        resolveRealmRelyingParty('auth.example.com', {
          rpId: 'auth.example.com',
          allowParentDomainRpId: false,
        })
      )
    ).toBe(true);
  });

  it('takes an opted-in parent domain with a warning, and then serves no association file', () => {
    const relyingParty = resolveRealmRelyingParty('auth.example.com', {
      rpId: 'example.com',
      allowParentDomainRpId: true,
    });
    expect(relyingParty).toMatchObject({ rpId: 'example.com', scope: 'parent-domain' });
    expect(relyingParty.warning).toContain('QAuth serves no app association files in this mode');
    expect(servesAssociationFiles(relyingParty)).toBe(false);
  });

  it.each([
    [
      'a parent domain without the opt-in',
      'example.com',
      'Set WEBAUTHN_RP_ID_ALLOW_PARENT_DOMAIN=true to opt in, or unset WEBAUTHN_RP_ID to use the realm host.',
    ],
    ['an unrelated host', 'login.example.com', 'Unset WEBAUTHN_RP_ID to use the realm host.'],
    ['a public suffix', 'com', 'Unset WEBAUTHN_RP_ID to use the realm host.'],
  ])('refuses %s, naming the variable and the remedy', (_name, rpId, remedy) => {
    const resolve = () =>
      resolveRealmRelyingParty('auth.example.com', { rpId, allowParentDomainRpId: false });
    expect(resolve).toThrow(PasskeyRelyingPartyError);
    expect(resolve).toThrow(/^WEBAUTHN_RP_ID: /);
    expect(resolve).toThrow(remedy);
  });
});

describe('passkeyCeremonyOrigins', () => {
  it("puts the realm issuer's origin first, then the client's operator-set origins, once each", () => {
    const apk = 'android:apk-key-hash:sYUC8p5I9SxqFernBPHmDxz_YVZXmVJdW8s-m3RTTqE';
    expect(passkeyCeremonyOrigins({ issuer: 'https://auth.example.com' }, [])).toEqual([
      'https://auth.example.com',
    ]);
    expect(
      passkeyCeremonyOrigins({ issuer: 'https://auth.example.com:8443/auth' }, [
        apk,
        'https://auth.example.com:8443',
      ])
    ).toEqual(['https://auth.example.com:8443', apk]);
  });

  it('refuses a realm without an issuer, whose pages have no origin yet', () => {
    expect(() => passkeyCeremonyOrigins({ issuer: null }, [])).toThrow(RealmWithoutIssuerError);
  });
});
