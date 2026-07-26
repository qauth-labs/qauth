import { InvalidConfigurationError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { assertTrustedIssuersUsable } from './assert-trusted-issuers';
import { ValidatedIssuer } from './issuer-identity';
import { resolveTrustRegistry } from './resolve-trust-registry';

/**
 * The entry shapes that passed `server-config`'s `OID4VP_TRUSTED_ISSUERS`
 * schema — `z.url({ protocol: /^https$/ })` — and were then refused by the
 * runtime canonicalizer.
 *
 * Each one is an https URL, so `z.url` accepts it; each one carries userinfo, a
 * query string or a fragment, which `canonicalizeIssuerIdentifier` rejects
 * because they are not part of an issuer's identity and are how two spellings of
 * one issuer become two entries. This list IS the bug: the config layer said
 * yes, the trust layer said no, and nothing failed until a presentation arrived.
 */
const PASSES_SHAPE_VALIDATION_BUT_NOT_CANONICALIZATION: [string, string][] = [
  ['userinfo', 'https://user:pw@issuer.example'],
  ['a username alone', 'https://attacker@issuer.example'],
  ['a query string', 'https://issuer.example?x=1'],
  ['a fragment', 'https://issuer.example#frag'],
];

describe('assertTrustedIssuersUsable — config/runtime agreement (#236)', () => {
  it.each(PASSES_SHAPE_VALIDATION_BUT_NOT_CANONICALIZATION)(
    'refuses the boot on an entry with %s',
    (_label, entry) => {
      expect(() => assertTrustedIssuersUsable({ master: [entry] })).toThrow(
        InvalidConfigurationError
      );
    }
  );

  it.each(PASSES_SHAPE_VALIDATION_BUT_NOT_CANONICALIZATION)(
    'the entry with %s is exactly the shape that silently deny-alls a realm',
    (_label, entry) => {
      // The failure this assertion exists to prevent, demonstrated: without the
      // boot check, this configuration starts and then trusts NOBODY — the same
      // registry an unconfigured realm gets — with no error anywhere. Trust is
      // all-or-nothing per realm, so the one bad entry takes the good one with
      // it.
      const registry = resolveTrustRegistry(
        { name: 'master' },
        { OID4VP_TRUSTED_ISSUERS: { master: ['https://issuer.example', entry] } }
      );
      const good = ValidatedIssuer.fromValidatedPresentation({
        identifier: 'https://issuer.example',
        keyResolution: 'issuer-metadata',
      });

      expect(registry.isTrusted(good)).toBe(false);
    }
  );

  it.each([
    ['plain http', 'http://issuer.example'],
    ['a bare hostname', 'issuer.example'],
    ['a DID', 'did:example:123'],
    ['an empty entry', ''],
    ['a non-string entry', 42],
  ])('refuses the boot on %s', (_label, entry) => {
    expect(() => assertTrustedIssuersUsable({ master: [entry] as unknown as string[] })).toThrow(
      InvalidConfigurationError
    );
  });

  it('refuses a realm mapped to something that is not an array', () => {
    expect(() =>
      assertTrustedIssuersUsable({ master: 'https://issuer.example' } as unknown as Record<
        string,
        readonly string[]
      >)
    ).toThrow(InvalidConfigurationError);
  });

  it('refuses a map that is not an object at all', () => {
    expect(() =>
      assertTrustedIssuersUsable(['https://issuer.example'] as unknown as Record<
        string,
        readonly string[]
      >)
    ).toThrow(InvalidConfigurationError);
  });

  it.each([
    ['not configured at all', undefined],
    ['explicitly null', null],
  ])('starts when the allowlist is %s — no config is the fail-closed default', (_label, value) => {
    expect(() => assertTrustedIssuersUsable(value)).not.toThrow();
  });

  it('starts on an empty map and on a realm that trusts nobody', () => {
    expect(() => assertTrustedIssuersUsable({})).not.toThrow();
    expect(() => assertTrustedIssuersUsable({ master: [] })).not.toThrow();
  });

  it('starts on entries the trust registry can actually use', () => {
    expect(() =>
      assertTrustedIssuersUsable({
        master: ['https://issuer.example', 'https://Issuer.EXAMPLE:443/', 'https://a.example/t/'],
        acme: [],
      })
    ).not.toThrow();
  });

  it('keeps the operator-supplied value OUT of the message and ON details', () => {
    const entry = 'https://issuer.example?tenant=acme-secret';

    try {
      assertTrustedIssuersUsable({ 'realm-with-a-telling-name': [entry] });
      expect.unreachable('should have refused');
    } catch (error) {
      const configError = error as InvalidConfigurationError;

      expect(configError.message).not.toContain(entry);
      expect(configError.message).not.toContain('realm-with-a-telling-name');
      expect(configError.details).toEqual({
        realm: 'realm-with-a-telling-name',
        index: 0,
        entry,
      });
    }
  });

  it('truncates a long entry before putting it on details', () => {
    const entry = `https://issuer.example/${'a'.repeat(400)}?x=1`;

    try {
      assertTrustedIssuersUsable({ master: [entry] });
      expect.unreachable('should have refused');
    } catch (error) {
      const reported = (error as InvalidConfigurationError).details?.['entry'];

      expect(typeof reported).toBe('string');
      expect(reported as string).toHaveLength(121);
      expect(reported as string).toMatch(/…$/);
    }
  });

  it('reports the position of the offending entry, which is not operator text', () => {
    try {
      assertTrustedIssuersUsable({
        master: ['https://a.example', 'https://b.example', 'https://c.example#f'],
      });
      expect.unreachable('should have refused');
    } catch (error) {
      expect((error as InvalidConfigurationError).details?.['index']).toBe(2);
    }
  });
});
