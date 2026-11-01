import { PRIVATE_JWK_MEMBERS } from '@qauth-labs/shared-validation';
import { describe, expect, it } from 'vitest';

import { publicJwkSchema } from './public-jwk';

const OKP = { kty: 'OKP', crv: 'Ed25519', x: '11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo' };
const EC = { kty: 'EC', crv: 'P-256', x: 'eA', y: 'eQ' };
const RSA = { kty: 'RSA', n: 'bg', e: 'AQAB' };

describe('publicJwkSchema', () => {
  it('accepts a public OKP, EC and RSA key, and a key type it does not know', () => {
    for (const jwk of [OKP, EC, RSA, { kty: 'AKP', alg: 'ML-DSA-65', pub: 'cA' }]) {
      expect(publicJwkSchema.safeParse(jwk).success, JSON.stringify(jwk)).toBe(true);
    }
  });

  // An RSA key can carry its primes or CRT values without `d`.
  it('refuses every private member, the RSA primes and CRT values among them', () => {
    for (const member of PRIVATE_JWK_MEMBERS) {
      const result = publicJwkSchema.safeParse({ ...RSA, [member]: 'c2VjcmV0' });
      expect(result.success, member).toBe(false);
      expect(result.error?.issues[0]?.message, member).toContain('PUBLIC keys only');
    }
  });

  it('refuses a key of a known type without the public members it needs', () => {
    for (const jwk of [
      { kty: 'OKP' },
      { kty: 'OKP', crv: 'Ed25519' },
      { kty: 'EC', crv: 'P-256', x: 'eA' },
      { kty: 'RSA', n: 'bg' },
      { kty: 'RSA', n: '', e: 'AQAB' },
    ]) {
      expect(publicJwkSchema.safeParse(jwk).success, JSON.stringify(jwk)).toBe(false);
    }
  });
});
