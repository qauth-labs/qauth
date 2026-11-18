import { describe, expect, it } from 'vitest';

import {
  ACT_CHAIN_TOKEN_AUDIENCE,
  ACT_CHAIN_TOKEN_CLAIMS,
  ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS,
  actChainTokenClaimsProblem,
} from './act-chain-token-claims';

const NOW = 1_800_000_000;

/** An act-chain token's claims as the admin API asks for them (#523). */
function actChain(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sub: 'user-1',
    aud: ACT_CHAIN_TOKEN_AUDIENCE,
    act: { sub: 'admin-1', iss: 'https://auth.example.test/realms/operator', client_id: 'console' },
    cnf: { jkt: 'thumbprint' },
    jti: 'token-1',
    client_id: 'console',
    scope: 'qauth:account:read',
    token_use: 'access',
    iat: NOW,
    exp: NOW + ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS,
    ...overrides,
  };
}

describe('actChainTokenClaimsProblem (#523)', () => {
  it('accepts an act-chain token: the user as sub, the admin as act, the account audience, bound and short-lived', () => {
    expect(actChainTokenClaimsProblem(actChain(), NOW)).toBeUndefined();
    expect(
      actChainTokenClaimsProblem(actChain({ scope: 'qauth:account:read qauth:account:write' }), NOW)
    ).toBeUndefined();
    expect(ACT_CHAIN_TOKEN_CLAIMS).not.toContain('auth_time');
  });

  it.each([
    ['a sign-in time', { auth_time: NOW }],
    ['sign-in methods', { amr: ['pwd'] }],
    ['a session', { sid: 'session-1' }],
    ['an ID token claim', { nonce: 'n' }],
    ['an email claim', { email: 'user@example.test' }],
    ['another audience', { aud: 'https://api.example.test' }],
    ['an audience list', { aud: [ACT_CHAIN_TOKEN_AUDIENCE] }],
    ['an unbound token', { cnf: undefined }],
    ['a confirmation beside jkt', { cnf: { jkt: 'thumbprint', x5t: 'other' } }],
    ['no actor', { act: undefined }],
    ['an actor without an issuer', { act: { sub: 'admin-1', client_id: 'console' } }],
    [
      'a nested actor',
      {
        act: {
          sub: 'admin-1',
          iss: 'https://auth.example.test',
          client_id: 'console',
          act: { sub: 'agent' },
        },
      },
    ],
    [
      "an actor's client that is not the token's",
      { act: { sub: 'admin-1', iss: 'https://auth.example.test', client_id: 'other' } },
    ],
    ['a scope of another API', { scope: 'qauth:account:read openid' }],
    ['a scope named twice', { scope: 'qauth:account:read qauth:account:read' }],
    ['no scope', { scope: '' }],
    ['a refresh token use', { token_use: 'refresh' }],
    ['no jti', { jti: undefined }],
    ['a lifetime over ten minutes', { exp: NOW + ACT_CHAIN_TOKEN_MAX_LIFETIME_SECONDS + 1 }],
    ['an exp before iat', { exp: NOW - 1 }],
    ['an iat far from the signer clock', { iat: NOW - 3_600, exp: NOW - 3_000 }],
    ['a fractional iat', { iat: NOW + 0.5 }],
  ])('refuses %s', (_case, overrides) => {
    const claims = actChain(overrides);
    for (const [name, value] of Object.entries(overrides)) {
      if (value === undefined) delete claims[name];
    }
    expect(actChainTokenClaimsProblem(claims, NOW)).toEqual(expect.any(String));
  });

  it('names a claim in its refusal, never a value', () => {
    const problem = actChainTokenClaimsProblem(actChain({ email: 'secret@example.test' }), NOW);
    expect(problem).toContain("'email'");
    expect(problem).not.toContain('secret@example.test');
  });
});
