import { describe, expect, it } from 'vitest';

import { PRIVATE_JWK_MEMBERS, publicJwkProblem } from './public-jwk';

const OKP = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
const EC = { kty: 'EC', crv: 'P-256', x: 'eA', y: 'eQ' };
const RSA = { kty: 'RSA', n: 'bg', e: 'AQAB' };

describe('publicJwkProblem (#925, #935)', () => {
  it('finds nothing wrong with a public OKP, EC and RSA key, or a key type it does not know', () => {
    for (const jwk of [OKP, EC, RSA, { kty: 'AKP', alg: 'ML-DSA-65', pub: 'cA' }]) {
      expect(publicJwkProblem(jwk), JSON.stringify(jwk)).toBeUndefined();
    }
  });

  it('lists every private member of RFC 7518 and ML-DSA', () => {
    expect([...PRIVATE_JWK_MEMBERS].sort()).toEqual(
      ['d', 'dp', 'dq', 'k', 'oth', 'p', 'priv', 'q', 'qi'].sort()
    );
  });

  it('refuses every private member, by name, whatever its value', () => {
    for (const member of PRIVATE_JWK_MEMBERS) {
      for (const value of ['c2VjcmV0', '', null, [[['deep']]], {}]) {
        expect(publicJwkProblem({ ...RSA, [member]: value }), member).toEqual({
          kind: 'private',
          members: [member],
          message: `jwks must contain PUBLIC keys only (private member "${member}" present)`,
        });
      }
    }
  });

  // An RSA key can carry its primes and CRT values without `d` (#935).
  it('names each private member an RSA key without d carries', () => {
    expect(
      publicJwkProblem({ ...RSA, p: 'cA', q: 'cQ', dp: 'ZA', dq: 'ZQ', qi: 'cWk' })
    ).toMatchObject({ kind: 'private', members: ['p', 'q', 'dp', 'dq', 'qi'] });
  });

  it('names the public members a key of a known type lacks', () => {
    expect(publicJwkProblem({ kty: 'OKP' })).toEqual({
      kind: 'incomplete',
      members: ['crv', 'x'],
      message: 'a OKP key needs "crv", "x"',
    });
    for (const [jwk, missing] of [
      [{ kty: 'OKP', crv: 'Ed25519' }, ['x']],
      [{ kty: 'EC', crv: 'P-256', x: 'eA' }, ['y']],
      [{ kty: 'RSA', n: 'bg' }, ['e']],
      [{ kty: 'RSA', n: '', e: 'AQAB' }, ['n']],
      [{ kty: 'RSA', n: 1, e: 'AQAB' }, ['n']],
    ] as const) {
      expect(publicJwkProblem(jwk), JSON.stringify(jwk)).toMatchObject({
        kind: 'incomplete',
        members: missing,
      });
    }
  });

  it('needs nothing of a kty that only names an inherited property', () => {
    for (const kty of ['constructor', 'toString', '__proto__', 'hasOwnProperty']) {
      expect(publicJwkProblem({ kty }), kty).toBeUndefined();
    }
  });
});
