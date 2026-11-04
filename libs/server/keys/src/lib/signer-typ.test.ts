import { describe, expect, it } from 'vitest';

import {
  CLIENT_ASSERTION_TYP,
  isJwsSigningPurpose,
  isTypAllowed,
  isVerificationKeyPurpose,
  JWS_SIGNING_PURPOSES,
  JWS_TYP_BY_PURPOSE,
  OID4VP_REQUEST_OBJECT_TYP,
  REALM_JWKS_PURPOSES,
  VERIFICATION_KEY_PURPOSES,
} from './signer-typ';

describe('JWS_TYP_BY_PURPOSE', () => {
  it('binds token signing to access tokens, ID tokens and ID-JAGs, event signing to SETs and logout tokens', () => {
    expect(JWS_TYP_BY_PURPOSE).toEqual({
      token_signing: ['at+jwt', 'JWT', 'oauth-id-jag+jwt'],
      event_signing: ['secevent+jwt', 'logout+jwt'],
    });
    expect(JWS_SIGNING_PURPOSES).toEqual(['token_signing', 'event_signing']);
  });

  it('publishes the event signing keys in the realm JWKS after the token keys, for logout tokens (Back-Channel Logout 1.0 §2.6, #624)', () => {
    expect(REALM_JWKS_PURPOSES).toEqual(['token_signing', 'event_signing']);
    expect(Object.isFrozen(REALM_JWKS_PURPOSES)).toBe(true);
  });

  it('shares no typ between purposes', () => {
    expect(
      JWS_TYP_BY_PURPOSE.token_signing.filter((typ) =>
        (JWS_TYP_BY_PURPOSE.event_signing as readonly string[]).includes(typ)
      )
    ).toEqual([]);
  });

  it('is frozen', () => {
    expect(Object.isFrozen(JWS_TYP_BY_PURPOSE)).toBe(true);
    expect(Object.isFrozen(JWS_TYP_BY_PURPOSE.token_signing)).toBe(true);
    expect(Object.isFrozen(JWS_SIGNING_PURPOSES)).toBe(true);
  });
});

describe('isTypAllowed', () => {
  it('compares exactly', () => {
    expect(isTypAllowed('token_signing', 'at+jwt')).toBe(true);
    expect(isTypAllowed('token_signing', 'AT+JWT')).toBe(false);
    expect(isTypAllowed('token_signing', 'application/at+jwt')).toBe(false);
    expect(isTypAllowed('event_signing', 'at+jwt')).toBe(false);
    expect(isTypAllowed('token_signing', undefined)).toBe(false);
  });
});

describe('isJwsSigningPurpose', () => {
  it.each(['cookie_hmac', 'federation_entity', 'toString', '__proto__', undefined])(
    'refuses %s',
    (purpose) => {
      expect(isJwsSigningPurpose(purpose)).toBe(false);
    }
  );
});

describe('the OID4VP request key (#546)', () => {
  it('signs request objects with the RFC 9101 typ, which no signJws purpose signs', () => {
    expect(OID4VP_REQUEST_OBJECT_TYP).toBe('oauth-authz-req+jwt');
    expect(OID4VP_REQUEST_OBJECT_TYP).not.toBe(CLIENT_ASSERTION_TYP);
    for (const purpose of JWS_SIGNING_PURPOSES) {
      expect(isTypAllowed(purpose, OID4VP_REQUEST_OBJECT_TYP), purpose).toBe(false);
    }
    expect(isJwsSigningPurpose('oid4vp_request_signing')).toBe(false);
  });

  it('lists its verification keys besides the signJws purposes, and nothing else', () => {
    expect(VERIFICATION_KEY_PURPOSES).toEqual([
      'token_signing',
      'event_signing',
      'oid4vp_request_signing',
    ]);
    expect(Object.isFrozen(VERIFICATION_KEY_PURPOSES)).toBe(true);
    expect(REALM_JWKS_PURPOSES).not.toContain('oid4vp_request_signing');
    for (const purpose of VERIFICATION_KEY_PURPOSES) {
      expect(isVerificationKeyPurpose(purpose), purpose).toBe(true);
    }
    for (const purpose of [
      'oid4vp_response_encryption',
      'cookie_hmac',
      'data_at_rest',
      'upstream_client_assertion',
      'toString',
      undefined,
    ]) {
      expect(isVerificationKeyPurpose(purpose), String(purpose)).toBe(false);
    }
  });
});
