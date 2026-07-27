import { describe, expect, it } from 'vitest';

import { type AssuranceEnv, assuranceEnvSchema } from './assurance';

function parse(raw?: string): AssuranceEnv['OID4VP_ISSUER_ASSURANCE'] {
  return assuranceEnvSchema.parse(raw === undefined ? {} : { OID4VP_ISSUER_ASSURANCE: raw })
    .OID4VP_ISSUER_ASSURANCE;
}

function parseStyle(raw?: string): AssuranceEnv['ACR_VALUE_STYLE'] {
  return assuranceEnvSchema.parse(raw === undefined ? {} : { ACR_VALUE_STYLE: raw })
    .ACR_VALUE_STYLE;
}

describe('assuranceEnvSchema (OID4VP_ISSUER_ASSURANCE — #237)', () => {
  it('yields an empty map when unset — no realm assures any issuer, so no acr is emitted', () => {
    expect(parse()).toEqual({});
  });

  it.each([
    ['an empty string', ''],
    ['spaces', '   '],
    ['a newline', '\n'],
  ])('reads %s as unset rather than throwing', (_label, raw) => {
    // `parseEnv` parses the whole composed env in one `.parse()` at import, so
    // throwing on a `${VAR:-}` would take down password login for a deployment
    // with no interest in wallet federation.
    expect(parse(raw)).toEqual({});
  });

  it('parses a per-realm, per-issuer policy', () => {
    const parsed = parse(
      '{"master":{"https://issuer.example":{"level":"high"}},"acme":{"https://a.example":{"level":"substantial","credentialTypes":["urn:pid"]}}}'
    );

    expect(parsed).toEqual({
      master: { 'https://issuer.example': { level: 'high' } },
      acme: { 'https://a.example': { level: 'substantial', credentialTypes: ['urn:pid'] } },
    });
  });

  it('does not canonicalize — that belongs to server-federation, applied to both sides', () => {
    const parsed = parse('{"master":{"https://Issuer.EXAMPLE:443/":{"level":"high"}}}');

    expect(Object.keys(parsed?.['master'] ?? {})).toEqual(['https://Issuer.EXAMPLE:443/']);
  });

  it('returns prototype-less maps at both levels', () => {
    const parsed = parse('{"master":{"https://issuer.example":{"level":"high"}}}');

    expect(Object.getPrototypeOf(parsed)).toBeNull();
    expect(Object.getPrototypeOf(parsed?.['master'])).toBeNull();
  });

  it('freezes the parsed policy so nothing can widen it at run time', () => {
    const parsed = parse('{"master":{"https://issuer.example":{"level":"high"}}}');

    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed?.['master'])).toBe(true);
    expect(Object.isFrozen(parsed?.['master']?.['https://issuer.example'])).toBe(true);
  });

  it.each([
    ['not JSON at all', 'https://issuer.example'],
    ['a bare array', '["https://issuer.example"]'],
    ['a JSON string', '"master"'],
    ['null', 'null'],
    ['an issuer map that is an array', '{"master":["https://issuer.example"]}'],
    ['a bare level string instead of a statement', '{"master":{"https://issuer.example":"high"}}'],
    ['a missing level', '{"master":{"https://issuer.example":{}}}'],
    ['a level of low', '{"master":{"https://issuer.example":{"level":"low"}}}'],
    ['an unknown level', '{"master":{"https://issuer.example":{"level":"HIGH"}}}'],
    ['an http issuer', '{"master":{"http://issuer.example":{"level":"high"}}}'],
    ['a non-URL issuer', '{"master":{"issuer.example":{"level":"high"}}}'],
    [
      'an unknown statement member',
      '{"master":{"https://issuer.example":{"level":"high","trustAnchor":"x"}}}',
    ],
    [
      'an empty credentialTypes list',
      '{"master":{"https://issuer.example":{"level":"high","credentialTypes":[]}}}',
    ],
    [
      'a blank credential type',
      '{"master":{"https://issuer.example":{"level":"high","credentialTypes":[""]}}}',
    ],
    ['an empty realm name', '{"":{"https://issuer.example":{"level":"high"}}}'],
  ])('rejects %s outright rather than degrading silently', (_label, raw) => {
    // A typo must not land on the same behaviour as the legitimate default
    // ("assures nothing") — the operator would have no way to tell them apart.
    expect(() => parse(raw)).toThrow();
  });

  it.each([
    ['a realm named __proto__', '{"__proto__":{"https://issuer.example":{"level":"high"}}}'],
    ['a realm named constructor', '{"constructor":{"https://issuer.example":{"level":"high"}}}'],
    ['an issuer key named __proto__', '{"master":{"__proto__":{"level":"high"}}}'],
  ])('rejects %s rather than dropping it silently', (_label, raw) => {
    expect(() => parse(raw)).toThrow();
  });

  it('rejects a realm assuring more issuers than the cap allows', () => {
    const issuers = Object.fromEntries(
      Array.from({ length: 65 }, (_, i) => [`https://issuer-${i}.example`, { level: 'high' }])
    );

    expect(() => parse(JSON.stringify({ master: issuers }))).toThrow();
  });
});

describe('assuranceEnvSchema (ACR_VALUE_STYLE — #237)', () => {
  it('defaults to the eIDAS URI form, which OIDC Core §2 asks an acr value to be', () => {
    expect(parseStyle()).toBe('eidas-uri');
  });

  it.each([
    ['an empty string', ''],
    ['spaces', '   '],
  ])('reads %s as unset and applies the default', (_label, raw) => {
    expect(parseStyle(raw)).toBe('eidas-uri');
  });

  it('accepts the bare-name vocabulary', () => {
    expect(parseStyle('loa-name')).toBe('loa-name');
  });

  it.each([
    ['an unknown vocabulary', 'eidas-saml'],
    ['a free-text value', 'urn:acme:loa:high'],
    ['a differently-cased value', 'EIDAS-URI'],
  ])('rejects %s — a free-text acr value could collide with a registered name', (_label, raw) => {
    expect(() => parseStyle(raw)).toThrow();
  });
});
