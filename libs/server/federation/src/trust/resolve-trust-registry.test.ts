import { describe, expect, it } from 'vitest';

import { ValidatedIssuer } from './issuer-identity';
import {
  resolveTrustRegistry,
  type TrustRegistryEnvLike,
  type TrustRegistryRealmLike,
} from './resolve-trust-registry';

function validated(identifier: string): ValidatedIssuer {
  return ValidatedIssuer.fromValidatedPresentation({
    identifier,
    keyResolution: 'issuer-metadata',
  });
}

const ENV: TrustRegistryEnvLike = {
  OID4VP_TRUSTED_ISSUERS: {
    master: ['https://issuer.example'],
    acme: ['https://acme-issuer.example', 'https://acme-backup.example'],
    empty: [],
  },
};

describe('resolveTrustRegistry — env-configured realms (#236)', () => {
  it("trusts an issuer on the realm's list", () => {
    const registry = resolveTrustRegistry({ name: 'master' }, ENV);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(true);
  });

  it('is PER REALM — one realm never inherits another realm’s issuers', () => {
    // The core reason the config is a map and not a single global list.
    const master = resolveTrustRegistry({ name: 'master' }, ENV);
    const acme = resolveTrustRegistry({ name: 'acme' }, ENV);

    expect(master.isTrusted(validated('https://acme-issuer.example'))).toBe(false);
    expect(acme.isTrusted(validated('https://issuer.example'))).toBe(false);
    expect(acme.isTrusted(validated('https://acme-issuer.example'))).toBe(true);
    expect(acme.isTrusted(validated('https://acme-backup.example'))).toBe(true);
  });

  it('trusts nobody for a realm configured with an empty list', () => {
    const registry = resolveTrustRegistry({ name: 'empty' }, ENV);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it('trusts nobody for a realm absent from the map', () => {
    const registry = resolveTrustRegistry({ name: 'unknown-realm' }, ENV);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });
});

describe('resolveTrustRegistry — fail-closed (#236)', () => {
  it.each([
    ['no realm and no env', undefined, undefined],
    ['a realm but no env at all', { name: 'master' }, undefined],
    ['a null env', { name: 'master' }, null],
    ['env with the variable unset', { name: 'master' }, {}],
    ['env with an empty map', { name: 'master' }, { OID4VP_TRUSTED_ISSUERS: {} }],
    ['a null realm', null, ENV],
    ['a realm with no name', {}, ENV],
    ['a realm named with whitespace', { name: '   ' }, ENV],
    ['a realm with a null name', { name: null }, ENV],
  ])('trusts nobody with %s', (_label, realm, env) => {
    const registry = resolveTrustRegistry(
      realm as TrustRegistryRealmLike | null | undefined,
      env as TrustRegistryEnvLike | null | undefined
    );

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it('never throws on a corrupt env value — a bad config must not 500 a request', () => {
    const corrupt = {
      OID4VP_TRUSTED_ISSUERS: {
        master: 'https://issuer.example',
      } as unknown as Record<string, readonly string[]>,
    };

    expect(() => resolveTrustRegistry({ name: 'master' }, corrupt)).not.toThrow();
    expect(
      resolveTrustRegistry({ name: 'master' }, corrupt).isTrusted(
        validated('https://issuer.example')
      )
    ).toBe(false);
  });

  it('does not walk the prototype chain for a realm named after an Object member', () => {
    // `OID4VP_TRUSTED_ISSUERS` is operator-authored JSON, and a plain lookup of
    // `map['constructor']` returns `Object`, not an allowlist.
    const registry = resolveTrustRegistry({ name: 'constructor' }, ENV);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
    expect(() => resolveTrustRegistry({ name: 'toString' }, ENV)).not.toThrow();
  });
});

describe('resolveTrustRegistry — realm-level policy takes over (#236)', () => {
  // No `realms.trusted_issuers` column exists yet; this is the seam #299 also
  // shipped, so the column can land later without touching any call site.

  it("uses the realm's own list when present", () => {
    const registry = resolveTrustRegistry(
      { name: 'master', trustedIssuers: ['https://realm-issuer.example'] },
      ENV
    );

    expect(registry.isTrusted(validated('https://realm-issuer.example'))).toBe(true);
  });

  it('does NOT consult the env map once the realm has stated a policy', () => {
    // Substituting a deployment-wide value for a realm that stated its own is
    // how a narrow allowlist silently becomes a wide one.
    const registry = resolveTrustRegistry(
      { name: 'master', trustedIssuers: ['https://realm-issuer.example'] },
      ENV
    );

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it('treats an explicit empty realm list as "trusts nobody", not as "unset"', () => {
    const registry = resolveTrustRegistry({ name: 'master', trustedIssuers: [] }, ENV);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it('falls back to the env map only when the realm list is absent', () => {
    for (const realm of [
      { name: 'master' },
      { name: 'master', trustedIssuers: null },
      { name: 'master', trustedIssuers: undefined },
    ] satisfies TrustRegistryRealmLike[]) {
      expect(resolveTrustRegistry(realm, ENV).isTrusted(validated('https://issuer.example'))).toBe(
        true
      );
    }
  });

  it('denies the WHOLE realm list when one entry is malformed — never a partial policy', () => {
    // Honouring the valid subset would apply a trust policy the operator never
    // wrote, with no signal that it had been altered.
    const registry = resolveTrustRegistry(
      {
        name: 'master',
        trustedIssuers: ['https://good.example', 'http://bad.example'],
      },
      ENV
    );

    expect(registry.isTrusted(validated('https://good.example'))).toBe(false);
  });

  it('does not fall back to env when the realm list is malformed', () => {
    // Falling back would REPLACE a deliberate policy with a different one.
    const registry = resolveTrustRegistry({ name: 'master', trustedIssuers: ['not-a-url'] }, ENV);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it.each([
    ['a string instead of an array', 'https://issuer.example'],
    ['a number', 7],
    ['an object', { '0': 'https://issuer.example' }],
    ['an array holding a non-string', ['https://good.example', 42]],
  ])('trusts nobody when the realm column holds %s', (_label, corrupt) => {
    const registry = resolveTrustRegistry(
      { name: 'master', trustedIssuers: corrupt as unknown as readonly string[] },
      ENV
    );

    expect(registry.isTrusted(validated('https://good.example'))).toBe(false);
    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it('canonicalizes realm-supplied entries the same way env entries are', () => {
    const registry = resolveTrustRegistry(
      { name: 'master', trustedIssuers: ['https://Realm-Issuer.EXAMPLE:443/'] },
      ENV
    );

    expect(registry.isTrusted(validated('https://realm-issuer.example'))).toBe(true);
  });
});
