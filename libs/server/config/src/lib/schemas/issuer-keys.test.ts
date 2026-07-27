import { describe, expect, it } from 'vitest';

import { issuerKeysEnvSchema } from './issuer-keys';

/**
 * `OID4VP_ISSUER_JWKS` (#234/#236/#238).
 *
 * The variable that makes a Verifiable Presentation verifiable at all. Its
 * failure modes are all configuration mistakes, and each one has to fail LOUDLY
 * rather than degrade to "no keys" — because "no keys" is also the legitimate
 * default, and an operator cannot tell a typo from an intentional absence if the
 * two produce the same state.
 */

const P256_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU',
  y: 'x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0',
  kid: 'k1',
};

function parse(raw: string | undefined) {
  return issuerKeysEnvSchema.safeParse({ OID4VP_ISSUER_JWKS: raw });
}

describe('OID4VP_ISSUER_JWKS — fail-closed absence (#234)', () => {
  it.each([
    ['unset', undefined],
    ['empty', ''],
    ['whitespace', '   '],
    ['an empty object', '{}'],
  ] as const)('yields an empty map for %s rather than failing the boot', (_label, raw) => {
    const result = parse(raw);
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(Object.keys(result.data.OID4VP_ISSUER_JWKS)).toEqual([]);
  });

  it('produces a prototype-less map so an issuer identifier cannot address Object.prototype', () => {
    const result = parse(JSON.stringify({ 'https://issuer.example': [P256_JWK] }));
    expect(result.success).toBe(true);
    if (!result.success) return;

    const map = result.data.OID4VP_ISSUER_JWKS as Record<string, unknown>;
    expect(Object.getPrototypeOf(map)).toBeNull();
    expect(map['constructor']).toBeUndefined();
  });

  it('freezes the parsed key sets', () => {
    const result = parse(JSON.stringify({ 'https://issuer.example': [P256_JWK] }));
    expect(result.success).toBe(true);
    if (!result.success) return;

    const map = result.data.OID4VP_ISSUER_JWKS;
    expect(Object.isFrozen(map)).toBe(true);
    expect(Object.isFrozen(map['https://issuer.example'])).toBe(true);
    expect(Object.isFrozen(map['https://issuer.example']?.[0])).toBe(true);
  });
});

describe('OID4VP_ISSUER_JWKS — refusals (#236)', () => {
  it.each([
    ['not JSON', 'not-json'],
    ['a bare array', '[{"kty":"EC"}]'],
    ['a JSON string', '"https://issuer.example"'],
    ['null', 'null'],
  ] as const)('rejects %s rather than degrading to no keys', (_label, raw) => {
    expect(parse(raw).success).toBe(false);
  });

  it('rejects a non-HTTPS issuer identifier', () => {
    expect(parse(JSON.stringify({ 'http://issuer.example': [P256_JWK] })).success).toBe(false);
  });

  it('rejects an issuer with an empty key set', () => {
    // An issuer with no keys can never verify anything, so configuring one is
    // always a mistake — and a silent one, since it looks exactly like an issuer
    // whose credentials are all being rejected for a different reason.
    expect(parse(JSON.stringify({ 'https://issuer.example': [] })).success).toBe(false);
  });

  it('rejects a JWK with no kty', () => {
    expect(parse(JSON.stringify({ 'https://issuer.example': [{ x: 'a' }] })).success).toBe(false);
  });

  it.each(['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'])(
    'rejects a JWK carrying private member "%s"',
    (member) => {
      // An issuer's private key in a VERIFIER's configuration means a secret has
      // been mis-copied into an environment variable. The boot is where that
      // must be noticed.
      const raw = JSON.stringify({
        'https://issuer.example': [{ ...P256_JWK, [member]: 'secret' }],
      });
      expect(parse(raw).success).toBe(false);
    }
  );

  it.each(['__proto__', 'constructor', 'prototype'])(
    'rejects the prototype-addressing issuer name %s',
    (name) => {
      // `z.record` copies entries onto a plain object and loses `__proto__`
      // before any key validator sees it, so an operator-written entry would
      // vanish without a word. Refused explicitly instead.
      expect(parse(`{${JSON.stringify(name)}:[${JSON.stringify(P256_JWK)}]}`).success).toBe(false);
    }
  );

  it('rejects more keys for one issuer than the cap allows', () => {
    const jwks = Array.from({ length: 17 }, (_value, index) => ({ ...P256_JWK, kid: `k${index}` }));
    expect(parse(JSON.stringify({ 'https://issuer.example': jwks })).success).toBe(false);
  });
});

describe('OID4VP_ISSUER_JWKS — accepted shapes (#234)', () => {
  it('accepts several keys for one issuer (rotation)', () => {
    const result = parse(
      JSON.stringify({
        'https://issuer.example': [P256_JWK, { ...P256_JWK, kid: 'k2' }],
      })
    );
    expect(result.success).toBe(true);
    if (!result.success) return;
    expect(result.data.OID4VP_ISSUER_JWKS['https://issuer.example']).toHaveLength(2);
  });

  it('accepts several issuers, and keeps their key sets separate', () => {
    const result = parse(
      JSON.stringify({
        'https://a.example': [P256_JWK],
        'https://b.example': [{ ...P256_JWK, kid: 'other' }],
      })
    );
    expect(result.success).toBe(true);
    if (!result.success) return;

    const map = result.data.OID4VP_ISSUER_JWKS;
    expect(map['https://a.example']?.[0]?.['kid']).toBe('k1');
    expect(map['https://b.example']?.[0]?.['kid']).toBe('other');
  });

  it('accepts a key type this binary does not implement, leaving the crypto layer to refuse it', () => {
    // `kty` is open-ended and `importPublicSigningJwk` owns the decision. A
    // schema that enumerated key types would make adding one a config change in
    // two libraries.
    expect(
      parse(JSON.stringify({ 'https://issuer.example': [{ kty: 'OKP', crv: 'Ed25519', x: 'a' }] }))
        .success
    ).toBe(true);
  });
});
