import { describe, expect, it } from 'vitest';

import { type KeyAttestationEnv, keyAttestationEnvSchema } from './key-attestation';

function parse(raw?: string): KeyAttestationEnv['OID4VP_ATTESTING_ISSUERS'] {
  return keyAttestationEnvSchema.parse(raw === undefined ? {} : { OID4VP_ATTESTING_ISSUERS: raw })
    .OID4VP_ATTESTING_ISSUERS;
}

describe('keyAttestationEnvSchema (OID4VP_ATTESTING_ISSUERS — #308/#379)', () => {
  it('yields an empty map when unset — nothing attests, so nothing is provisioned', () => {
    expect(parse()).toEqual({});
  });

  it.each([
    ['an empty string', ''],
    ['spaces', '   '],
    ['a newline', '\n'],
  ])('reads %s as unset rather than throwing', (_label, raw) => {
    // `${VAR:-}` in a compose file is how an operator says "not configured", and
    // it must not take down a deployment with no interest in wallet federation.
    expect(parse(raw)).toEqual({});
  });

  it('parses an issuer → grade record', () => {
    expect(
      parse(
        '{"https://pid.member-state.example":"iso_18045_high","https://other.example":"iso_18045_moderate"}'
      )
    ).toEqual({
      'https://pid.member-state.example': 'iso_18045_high',
      'https://other.example': 'iso_18045_moderate',
    });
  });

  it('accepts every §D.2 grade, hyphen included', () => {
    for (const grade of [
      'iso_18045_basic',
      'iso_18045_enhanced-basic',
      'iso_18045_moderate',
      'iso_18045_high',
    ]) {
      expect(parse(`{"https://issuer.example":"${grade}"}`)).toEqual({
        'https://issuer.example': grade,
      });
    }
  });

  it('returns a prototype-less, frozen map', () => {
    // A lookup by an attacker-influenced issuer identifier must not walk
    // Object.prototype, and nothing may widen the record at run time.
    const parsed = parse('{"https://issuer.example":"iso_18045_high"}');

    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(Object.isFrozen(parsed)).toBe(true);
  });

  it.each([
    ['not JSON at all', 'https://issuer.example'],
    ['a bare array', '["https://issuer.example"]'],
    ['a JSON string', '"https://issuer.example"'],
    ['null', 'null'],
    ['an http issuer', '{"http://issuer.example":"iso_18045_high"}'],
    ['a non-URL issuer', '{"issuer.example":"iso_18045_high"}'],
    ['a grade this build does not understand', '{"https://issuer.example":"iso_18045_supreme"}'],
    [
      'the hyphen tidied out of enhanced-basic',
      '{"https://issuer.example":"iso_18045_enhanced_basic"}',
    ],
    ['an eIDAS level where a §D.2 grade belongs', '{"https://issuer.example":"high"}'],
    ['a nested object instead of a grade', '{"https://issuer.example":{"keyStorage":"high"}}'],
    ['a boolean instead of a grade', '{"https://issuer.example":true}'],
  ])('rejects %s outright rather than degrading silently', (_label, raw) => {
    // A typo must not land on the same behaviour as the legitimate default
    // ("nothing attests") — the operator would have no way to tell them apart,
    // and the symptom is every wallet user silently failing to reach the
    // assurance their credential should carry.
    expect(() => parse(raw)).toThrow();
  });

  it.each([
    ['__proto__', '{"__proto__":"iso_18045_high"}'],
    ['constructor', '{"constructor":"iso_18045_high"}'],
    ['prototype', '{"prototype":"iso_18045_high"}'],
  ])('rejects an issuer key named %s rather than dropping it silently', (_label, raw) => {
    expect(() => parse(raw)).toThrow();
  });

  it('rejects more issuers than the cap allows', () => {
    const issuers = Object.fromEntries(
      Array.from({ length: 65 }, (_, i) => [`https://issuer-${i}.example`, 'iso_18045_high'])
    );

    expect(() => parse(JSON.stringify(issuers))).toThrow();
  });
});
