import { describe, expect, it } from 'vitest';

import {
  isJwsSigningPurpose,
  isTypAllowed,
  JWS_SIGNING_PURPOSES,
  JWS_TYP_BY_PURPOSE,
  REALM_JWKS_PURPOSES,
} from './signer-typ';

describe('JWS_TYP_BY_PURPOSE', () => {
  it('binds token signing to access and ID tokens, event signing to SETs and logout tokens', () => {
    expect(JWS_TYP_BY_PURPOSE).toEqual({
      token_signing: ['at+jwt', 'JWT'],
      event_signing: ['secevent+jwt', 'logout+jwt'],
    });
    expect(JWS_SIGNING_PURPOSES).toEqual(['token_signing', 'event_signing']);
    expect(REALM_JWKS_PURPOSES).toEqual(['token_signing', 'event_signing']);
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
