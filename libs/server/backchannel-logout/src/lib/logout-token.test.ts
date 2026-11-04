import { randomUUID } from 'node:crypto';

import {
  decodeProtectedHeader,
  exportJWK,
  generateKeyPair,
  type JWTPayload,
  jwtVerify,
  SignJWT,
} from 'jose';
import { describe, expect, it } from 'vitest';

import {
  BACKCHANNEL_LOGOUT_EVENT,
  LOGOUT_TOKEN_LIFETIME_SECONDS,
  LOGOUT_TOKEN_TYP,
} from './constants';
import { logoutRequestBody, logoutTokenClaims } from './logout-token';

const ISSUER = 'https://auth.example.com/realms/acme';
const NOW = Date.UTC(2026, 10, 4, 9, 0, 0);
const USER = '0192a000-0000-7000-8000-0000000000bb';
const SID = '0192a000-0000-7000-8000-0000000000aa';

/**
 * What the signer does with the claims a route hands it: add `iss`, set the
 * `typ` and the key id, sign with the realm's `event_signing` key (EdDSA).
 */
async function signAsTheSigner(claims: Readonly<Record<string, unknown>>) {
  const { privateKey, publicKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const token = await new SignJWT({ iss: ISSUER, ...claims } as JWTPayload)
    .setProtectedHeader({ alg: 'EdDSA', typ: LOGOUT_TOKEN_TYP, kid: 'event-key' })
    .sign(privateKey);
  return { token, publicKey, jwk: await exportJWK(publicKey) };
}

/**
 * The checks of Back-Channel Logout 1.0 §2.6 a relying party makes on the
 * token (the §2.4 rules, read from the receiving side), with the clock at
 * `now`: what the delivered token must pass.
 */
async function validateAsTheRp(
  token: string,
  key: Awaited<ReturnType<typeof signAsTheSigner>>['publicKey'],
  audience: string,
  now: number
) {
  const { payload, protectedHeader } = await jwtVerify(token, key, {
    issuer: ISSUER,
    audience,
    currentDate: new Date(now),
    typ: LOGOUT_TOKEN_TYP,
    requiredClaims: ['iss', 'aud', 'iat', 'exp', 'jti', 'events'],
  });
  const events = payload['events'];
  if (
    events === null ||
    typeof events !== 'object' ||
    Array.isArray(events) ||
    !(BACKCHANNEL_LOGOUT_EVENT in events)
  ) {
    throw new Error('events claim lacks the back-channel logout member');
  }
  if (payload.sub === undefined && payload['sid'] === undefined) {
    throw new Error('neither sub nor sid');
  }
  if ('nonce' in payload) throw new Error('nonce present');
  return { payload, protectedHeader };
}

describe('logout token (OpenID Connect Back-Channel Logout 1.0 §2.4, #624)', () => {
  it('passes every check of §2.4 and §2.6 when signed as the signer signs it', async () => {
    const jti = randomUUID();
    const claims = logoutTokenClaims({ audience: 'rp', subject: USER, sid: SID, jti, now: NOW });
    const { token, publicKey } = await signAsTheSigner(claims);

    const { payload, protectedHeader } = await validateAsTheRp(token, publicKey, 'rp', NOW + 1_000);

    expect(protectedHeader).toEqual({ alg: 'EdDSA', typ: 'logout+jwt', kid: 'event-key' });
    expect(payload).toEqual({
      iss: ISSUER,
      aud: 'rp',
      iat: NOW / 1000,
      exp: NOW / 1000 + LOGOUT_TOKEN_LIFETIME_SECONDS,
      jti,
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
      sub: USER,
      sid: SID,
    });
  });

  it('carries no nonce (§2.4: PROHIBITED)', () => {
    const claims = logoutTokenClaims({
      audience: 'rp',
      subject: USER,
      sid: SID,
      jti: 'j',
      now: NOW,
    });
    expect(claims).not.toHaveProperty('nonce');
  });

  it('is explicitly typed logout+jwt, so it is never taken for an ID token (§2.4)', async () => {
    const { token } = await signAsTheSigner(
      logoutTokenClaims({ audience: 'rp', sid: SID, jti: 'j', now: NOW })
    );
    expect(decodeProtectedHeader(token).typ).toBe('logout+jwt');
  });

  it('the events member is the empty JSON object (§2.4)', () => {
    const { events } = logoutTokenClaims({ audience: 'rp', sid: SID, jti: 'j', now: NOW });
    expect(events).toEqual({ [BACKCHANNEL_LOGOUT_EVENT]: {} });
  });

  it('expires at most two minutes after it is issued, as the security considerations advise (§2.4 exp)', async () => {
    const claims = logoutTokenClaims({ audience: 'rp', sid: SID, jti: 'j', now: NOW });
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(120);
    const { token, publicKey } = await signAsTheSigner(claims);
    await expect(
      validateAsTheRp(token, publicKey, 'rp', NOW + (LOGOUT_TOKEN_LIFETIME_SECONDS + 1) * 1000)
    ).rejects.toThrow();
  });

  it('carries sub alone, sid alone, or both, and refuses to be built with neither (§2.4)', () => {
    expect(
      logoutTokenClaims({ audience: 'rp', subject: USER, jti: 'j', now: NOW })
    ).not.toHaveProperty('sid');
    expect(logoutTokenClaims({ audience: 'rp', sid: SID, jti: 'j', now: NOW })).not.toHaveProperty(
      'sub'
    );
    expect(() => logoutTokenClaims({ audience: 'rp', jti: 'j', now: NOW })).toThrow(
      'A logout token must carry a sub or a sid claim'
    );
  });

  it('is refused by a relying party it was not issued to (§2.4 aud)', async () => {
    const { token, publicKey } = await signAsTheSigner(
      logoutTokenClaims({ audience: 'rp', sid: SID, jti: 'j', now: NOW })
    );
    await expect(validateAsTheRp(token, publicKey, 'other-rp', NOW)).rejects.toThrow();
  });
});

describe('logout request body (OpenID Connect Back-Channel Logout 1.0 §2.5, #624)', () => {
  it('is the form-encoded logout_token parameter', () => {
    expect(logoutRequestBody('a.b-c_d.e')).toBe('logout_token=a.b-c_d.e');
    expect(new URLSearchParams(logoutRequestBody('x+y/z')).get('logout_token')).toBe('x+y/z');
  });
});
