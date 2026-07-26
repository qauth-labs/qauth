import { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { canonicalizeIssuerIdentifier, ValidatedIssuer } from './issuer-identity';
import { ISSUER_TRUST_REJECTION_MESSAGE } from './issuer-trust-rejection';

describe('canonicalizeIssuerIdentifier (#236)', () => {
  it.each([
    ['already canonical', 'https://issuer.example', 'https://issuer.example'],
    ['a trailing slash', 'https://issuer.example/', 'https://issuer.example'],
    ['repeated trailing slashes', 'https://issuer.example///', 'https://issuer.example'],
    ['an uppercase host', 'https://Issuer.EXAMPLE', 'https://issuer.example'],
    ['the default https port', 'https://issuer.example:443/', 'https://issuer.example'],
    ['surrounding whitespace', '  https://issuer.example  ', 'https://issuer.example'],
    [
      'a path with a trailing slash',
      'https://issuer.example/tenant/',
      'https://issuer.example/tenant',
    ],
  ])('reduces %s to the canonical form', (_label, raw, expected) => {
    expect(canonicalizeIssuerIdentifier(raw)).toBe(expected);
  });

  it('keeps a non-default port, which names a different issuer endpoint', () => {
    expect(canonicalizeIssuerIdentifier('https://issuer.example:8443/')).toBe(
      'https://issuer.example:8443'
    );
  });

  it('preserves path case — hosts are case-insensitive, paths are not', () => {
    expect(canonicalizeIssuerIdentifier('https://ISSUER.example/Tenant')).toBe(
      'https://issuer.example/Tenant'
    );
  });

  it('punycodes an internationalised host so two spellings cannot both be entries', () => {
    expect(canonicalizeIssuerIdentifier('https://büq.example')).toBe('https://xn--bq-xka.example');
  });

  it.each([
    ['plain http — an issuer identity readable in the clear', 'http://issuer.example'],
    ['a non-web scheme', 'did:example:123'],
    ['a bare hostname with no scheme', 'issuer.example'],
    ['userinfo, a classic look-alike trick', 'https://user:pw@issuer.example'],
    ['a username alone', 'https://attacker@issuer.example'],
    ['a query string, which is not part of an issuer identity', 'https://issuer.example?x=1'],
    ['a fragment', 'https://issuer.example#frag'],
    ['an empty string', ''],
    ['whitespace only', '   '],
    ['a relative path', '/issuer'],
  ])('rejects %s', (_label, raw) => {
    expect(canonicalizeIssuerIdentifier(raw)).toBeUndefined();
  });

  it.each([
    ['a number', 42],
    ['null', null],
    ['undefined', undefined],
    ['an object', { identifier: 'https://issuer.example' }],
    ['an array', ['https://issuer.example']],
  ])('rejects %s without throwing — untrusted JSON reaches this function', (_label, raw) => {
    expect(canonicalizeIssuerIdentifier(raw)).toBeUndefined();
  });

  it('rejects an identifier longer than the shared 2048-character cap', () => {
    const long = `https://issuer.example/${'a'.repeat(2048)}`;
    expect(canonicalizeIssuerIdentifier(long)).toBeUndefined();
  });

  it('accepts an identifier exactly at the cap', () => {
    const atCap = `https://issuer.example/${'a'.repeat(2048 - 'https://issuer.example/'.length)}`;
    expect(atCap).toHaveLength(2048);
    expect(canonicalizeIssuerIdentifier(atCap)).toBe(atCap);
  });
});

describe('ValidatedIssuer.fromValidatedPresentation (#236)', () => {
  it('canonicalizes the identifier it was handed', () => {
    const issuer = ValidatedIssuer.fromValidatedPresentation({
      identifier: 'https://Issuer.example:443/',
      keyResolution: 'issuer-metadata',
    });

    expect(issuer.identifier).toBe('https://issuer.example');
    expect(issuer.keyResolution).toBe('issuer-metadata');
  });

  it('records x5c resolution so a chain-validating backend can demand it later', () => {
    const issuer = ValidatedIssuer.fromValidatedPresentation({
      identifier: 'https://issuer.example',
      keyResolution: 'x5c',
    });

    expect(issuer.keyResolution).toBe('x5c');
  });

  it('is frozen — a validated identity must not be mutable after the fact', () => {
    const issuer = ValidatedIssuer.fromValidatedPresentation({
      identifier: 'https://issuer.example',
      keyResolution: 'x5c',
    });

    expect(Object.isFrozen(issuer)).toBe(true);
    expect(() => {
      (issuer as { identifier: string }).identifier = 'https://evil.example';
    }).toThrow();
    expect(issuer.identifier).toBe('https://issuer.example');
  });

  it('rejects a malformed identifier with the SAME error as an untrusted issuer', () => {
    // Non-enumeration: a distinct "malformed" error would let a caller tell a
    // broken credential apart from a good one whose issuer is not trusted.
    expect(() =>
      ValidatedIssuer.fromValidatedPresentation({
        identifier: 'http://issuer.example',
        keyResolution: 'x5c',
      })
    ).toThrow(InvalidCredentialsError);

    expect(() =>
      ValidatedIssuer.fromValidatedPresentation({
        identifier: 'http://issuer.example',
        keyResolution: 'x5c',
      })
    ).toThrow(ISSUER_TRUST_REJECTION_MESSAGE);
  });

  it('rejects an unknown key-resolution method arriving through a cast', () => {
    expect(() =>
      ValidatedIssuer.fromValidatedPresentation({
        identifier: 'https://issuer.example',
        keyResolution: 'trust-me' as 'x5c',
      })
    ).toThrow(InvalidCredentialsError);
  });

  it('rejects evidence that is not an object at all', () => {
    expect(() =>
      ValidatedIssuer.fromValidatedPresentation(
        undefined as unknown as { identifier: string; keyResolution: 'x5c' }
      )
    ).toThrow(InvalidCredentialsError);
  });
});

describe('ValidatedIssuer.isValidated — the forgery guard (#236)', () => {
  it('accepts an identity it produced', () => {
    const issuer = ValidatedIssuer.fromValidatedPresentation({
      identifier: 'https://issuer.example',
      keyResolution: 'x5c',
    });

    expect(ValidatedIssuer.isValidated(issuer)).toBe(true);
  });

  it('rejects an object literal shaped like a validated issuer', () => {
    // This is the raw, unverified `iss` case: an attacker-controlled string
    // dressed up as an identity. The compiler already refuses it without the
    // cast; the cast is what a careless caller would write.
    const forged = {
      identifier: 'https://issuer.example',
      keyResolution: 'x5c',
    } as unknown as ValidatedIssuer;

    expect(ValidatedIssuer.isValidated(forged)).toBe(false);
  });

  it('rejects an object built on the prototype — instanceof would have passed', () => {
    const forged = Object.assign(Object.create(ValidatedIssuer.prototype) as object, {
      identifier: 'https://issuer.example',
      keyResolution: 'x5c',
    }) as ValidatedIssuer;

    expect(forged).toBeInstanceOf(ValidatedIssuer);
    expect(ValidatedIssuer.isValidated(forged)).toBe(false);
  });

  it('rejects a JSON round-trip of a genuine identity', () => {
    const issuer = ValidatedIssuer.fromValidatedPresentation({
      identifier: 'https://issuer.example',
      keyResolution: 'x5c',
    });
    const revived = JSON.parse(JSON.stringify(issuer)) as ValidatedIssuer;

    expect(revived.identifier).toBe('https://issuer.example');
    expect(ValidatedIssuer.isValidated(revived)).toBe(false);
  });

  it.each([
    ['a raw iss string', 'https://issuer.example'],
    ['null', null],
    ['undefined', undefined],
    ['a number', 1],
    ['an array', []],
  ])('rejects %s', (_label, value) => {
    expect(ValidatedIssuer.isValidated(value)).toBe(false);
  });
});
