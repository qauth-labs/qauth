import { describe, expect, it } from 'vitest';

import { type TrustRegistryEnv, trustRegistryEnvSchema } from './trust-registry';

function parse(raw?: string): TrustRegistryEnv['OID4VP_TRUSTED_ISSUERS'] {
  return trustRegistryEnvSchema.parse(raw === undefined ? {} : { OID4VP_TRUSTED_ISSUERS: raw })
    .OID4VP_TRUSTED_ISSUERS;
}

describe('trustRegistryEnvSchema (OID4VP_TRUSTED_ISSUERS — #236)', () => {
  it('yields an empty map when unset — no realm trusts any issuer', () => {
    // Not `undefined`: a caller must not be able to mistake "not configured"
    // for "no opinion". Empty IS the refusing state (#296 posture, #236).
    expect(parse()).toEqual({});
  });

  it.each([
    ['an empty string', ''],
    ['spaces', '   '],
    ['a newline', '\n'],
  ])('reads %s as unset rather than throwing', (_label, raw) => {
    // `parseEnv` parses the whole composed auth-server env in one `.parse()` at
    // module import, so throwing on a `${VAR:-}` would take down password login
    // for a deployment with no interest in wallet federation.
    expect(parse(raw)).toEqual({});
  });

  it('parses a per-realm map', () => {
    const parsed = parse('{"master":["https://issuer.example"],"acme":[]}');

    expect(parsed).toEqual({
      master: ['https://issuer.example'],
      acme: [],
    });
  });

  it('accepts several issuers for one realm', () => {
    const parsed = parse('{"master":["https://a.example","https://b.example"]}');

    expect(parsed?.['master']).toEqual(['https://a.example', 'https://b.example']);
  });

  it('does not canonicalize — that belongs to server-federation, applied to both sides', () => {
    const parsed = parse('{"master":["https://Issuer.EXAMPLE:443/"]}');

    expect(parsed?.['master']).toEqual(['https://Issuer.EXAMPLE:443/']);
  });

  it('returns a prototype-less map so a realm named after an Object member cannot alias', () => {
    const parsed = parse('{"master":["https://issuer.example"]}');

    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect((parsed as Record<string, unknown>)['constructor']).toBeUndefined();
  });

  it.each(['__proto__', 'constructor', 'prototype'])(
    'rejects the prototype-addressing realm name %s rather than silently dropping it',
    (realmName) => {
      // Writing `__proto__` back onto a plain object re-invokes the setter and
      // the entry disappears — a trust policy the operator wrote and the server
      // did not apply. Failing loudly is the only honest outcome.
      expect(() => parse(JSON.stringify({ [realmName]: ['https://issuer.example'] }))).toThrow();
      expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
    }
  );

  it('deeply freezes the result', () => {
    const parsed = parse('{"master":["https://issuer.example"]}');

    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.['master'])).toBe(true);
  });
});

describe('trustRegistryEnvSchema — hard failures (#236)', () => {
  it.each([
    ['invalid JSON', '{not json'],
    ['a bare array with no realm to attach trust to', '["https://issuer.example"]'],
    ['a JSON string', '"https://issuer.example"'],
    ['JSON null', 'null'],
    ['a number', '7'],
    ['a realm mapped to a string instead of an array', '{"master":"https://issuer.example"}'],
    ['a realm mapped to null', '{"master":null}'],
    ['a non-string issuer', '{"master":[42]}'],
    ['an empty realm name', '{"":["https://issuer.example"]}'],
  ])('rejects %s at parse time so a typo fails the boot', (_label, raw) => {
    // A typo must not degrade to "trusts nothing" silently: that is also the
    // legitimate default, so the operator would have no way to tell them apart.
    expect(() => parse(raw)).toThrow();
  });

  it.each([
    ['plain http', 'http://issuer.example'],
    ['a bare hostname', 'issuer.example'],
    ['a DID', 'did:example:123'],
    ['an empty issuer', ''],
  ])('rejects the issuer entry %s', (_label, entry) => {
    expect(() => parse(JSON.stringify({ master: [entry] }))).toThrow();
  });

  it('names the variable in the failure message so an operator can find it', () => {
    expect(() => parse('{"master":["http://issuer.example"]}')).toThrow(/OID4VP_TRUSTED_ISSUERS/);
  });

  it('rejects a realm name longer than realms.name allows', () => {
    expect(() => parse(JSON.stringify({ ['a'.repeat(256)]: [] }))).toThrow();
  });

  it('rejects more than 64 issuers for one realm', () => {
    const issuers = Array.from({ length: 65 }, (_, i) => `https://issuer-${i}.example`);

    expect(() => parse(JSON.stringify({ master: issuers }))).toThrow();
    expect(() => parse(JSON.stringify({ master: issuers.slice(0, 64) }))).not.toThrow();
  });

  it('rejects more than 256 realms', () => {
    const many = Object.fromEntries(Array.from({ length: 257 }, (_, i) => [`realm-${i}`, []]));

    expect(() => parse(JSON.stringify(many))).toThrow();
  });

  it('rejects an issuer identifier longer than 2048 characters', () => {
    const long = `https://issuer.example/${'a'.repeat(2100)}`;

    expect(() => parse(JSON.stringify({ master: [long] }))).toThrow();
  });

  it('rejects a raw value larger than 64 KiB', () => {
    expect(() => parse('a'.repeat(64 * 1024 + 1))).toThrow();
  });
});

describe('trustRegistryEnvSchema — composition', () => {
  it('exposes a plain object shape so auth-server can spread it into its env schema', () => {
    // A `.superRefine()`/`.transform()`-wrapped OBJECT has no `.shape`; the
    // wrapping here is per field, which is fine.
    expect(Object.keys(trustRegistryEnvSchema.shape)).toEqual(['OID4VP_TRUSTED_ISSUERS']);
  });

  it('is separate from the verifier-profile config — the other trust direction', () => {
    // #299 owns `OID4VP_VERIFIER_PROFILE` (how QAuth proves it is the Verifier).
    // The two directions must never share configuration.
    expect(Object.keys(trustRegistryEnvSchema.shape)).not.toContain('OID4VP_VERIFIER_PROFILE');
  });
});
