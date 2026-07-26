import { InvalidCredentialsError } from '@qauth-labs/shared-errors';
import { describe, expect, it } from 'vitest';

import { type IssuerKeyResolutionMethod, ValidatedIssuer } from './issuer-identity';
import { ISSUER_TRUST_REJECTION_MESSAGE } from './issuer-trust-rejection';
import {
  assertIssuerTrusted,
  createStaticIssuerAllowlist,
  DENY_ALL_TRUST_REGISTRY,
  type TrustRegistry,
} from './trust-registry';

function validated(
  identifier: string,
  keyResolution: IssuerKeyResolutionMethod = 'issuer-metadata'
): ValidatedIssuer {
  return ValidatedIssuer.fromValidatedPresentation({ identifier, keyResolution });
}

describe('createStaticIssuerAllowlist (#236)', () => {
  it('trusts an issuer on the list', () => {
    const registry = createStaticIssuerAllowlist(['https://issuer.example']);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(true);
  });

  it('does not trust an issuer that is not on the list', () => {
    const registry = createStaticIssuerAllowlist(['https://issuer.example']);

    expect(registry.isTrusted(validated('https://other.example'))).toBe(false);
  });

  it('matches through canonicalization on BOTH sides', () => {
    // The entry and the validated identity are spelled differently; if only one
    // side were canonicalized, trust would silently fail (or silently succeed
    // on a near-match).
    const registry = createStaticIssuerAllowlist(['https://Issuer.EXAMPLE:443/']);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(true);
  });

  it('does not treat a sub-path as the issuer', () => {
    const registry = createStaticIssuerAllowlist(['https://issuer.example']);

    expect(registry.isTrusted(validated('https://issuer.example/evil'))).toBe(false);
  });

  it('does not treat a look-alike host as the issuer', () => {
    const registry = createStaticIssuerAllowlist(['https://issuer.example']);

    expect(registry.isTrusted(validated('https://issuer.example.evil.test'))).toBe(false);
    expect(registry.isTrusted(validated('https://evil.test/issuer.example'))).toBe(false);
  });

  it('trusts nobody when the list is empty — fail-closed, never accept-all', () => {
    const registry = createStaticIssuerAllowlist([]);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it('refuses a forged identity even when its identifier IS on the list', () => {
    // The whole point of #236: membership is checked against a VALIDATED
    // identity, so an unverified `iss` that happens to name a trusted issuer
    // grants nothing.
    const registry = createStaticIssuerAllowlist(['https://issuer.example']);
    const forged = {
      identifier: 'https://issuer.example',
      keyResolution: 'x5c',
    } as unknown as ValidatedIssuer;

    expect(registry.isTrusted(forged)).toBe(false);
  });

  it('deduplicates entries that canonicalize to the same issuer', () => {
    const registry = createStaticIssuerAllowlist([
      'https://issuer.example',
      'https://issuer.example/',
      'https://ISSUER.example:443',
    ]);

    expect(registry.isTrusted(validated('https://issuer.example'))).toBe(true);
  });

  it.each([
    ['plain http', 'http://issuer.example'],
    ['a bare hostname', 'issuer.example'],
    ['a DID', 'did:example:123'],
    ['an empty entry', ''],
  ])('throws loudly on the malformed entry %s rather than dropping it', (_label, entry) => {
    // Dropping it would leave the operator believing an issuer is trusted when
    // it is not; returning a deny-all registry would be indistinguishable from
    // a correctly-empty configuration.
    expect(() => createStaticIssuerAllowlist([entry])).toThrow(/not a usable issuer identity/);
  });

  it('names the offending entry in the operator-facing error, truncated', () => {
    const long = `http://issuer.example/${'a'.repeat(400)}`;

    expect(() => createStaticIssuerAllowlist([long])).toThrow(/…/);
  });

  it('throws when handed something that is not an array', () => {
    expect(() =>
      createStaticIssuerAllowlist('https://issuer.example' as unknown as string[])
    ).toThrow(/must be an array/);
  });

  it('is frozen so a caller cannot swap the decision function', () => {
    const registry = createStaticIssuerAllowlist(['https://issuer.example']);

    expect(Object.isFrozen(registry)).toBe(true);
  });
});

describe('DENY_ALL_TRUST_REGISTRY (#236)', () => {
  it('trusts nobody', () => {
    expect(DENY_ALL_TRUST_REGISTRY.isTrusted(validated('https://issuer.example'))).toBe(false);
  });

  it('is frozen', () => {
    expect(Object.isFrozen(DENY_ALL_TRUST_REGISTRY)).toBe(true);
  });
});

describe('assertIssuerTrusted — the mandatory gate (#236)', () => {
  const registry = createStaticIssuerAllowlist(['https://issuer.example']);

  it('passes a trusted issuer through', () => {
    expect(() => assertIssuerTrusted(registry, validated('https://issuer.example'))).not.toThrow();
  });

  it.each([
    [
      'an untrusted issuer',
      (): void => assertIssuerTrusted(registry, validated('https://other.example')),
    ],
    [
      'a realm with no registry at all',
      (): void => assertIssuerTrusted(undefined, validated('https://issuer.example')),
    ],
    ['a null registry', (): void => assertIssuerTrusted(null, validated('https://issuer.example'))],
    [
      'an empty allowlist',
      (): void =>
        assertIssuerTrusted(createStaticIssuerAllowlist([]), validated('https://issuer.example')),
    ],
    [
      'a forged identity naming a trusted issuer',
      (): void =>
        assertIssuerTrusted(registry, {
          identifier: 'https://issuer.example',
          keyResolution: 'x5c',
        } as unknown as ValidatedIssuer),
    ],
  ])('refuses %s', (_label, act) => {
    expect(act).toThrow(InvalidCredentialsError);
  });

  it('gives every refusal the identical, non-enumerating message', () => {
    // The security property: an attacker probing issuer by issuer cannot tell
    // "not on the list" from "no list configured" from "malformed".
    const refusals = [
      (): void => assertIssuerTrusted(registry, validated('https://other.example')),
      (): void => assertIssuerTrusted(undefined, validated('https://issuer.example')),
      (): void =>
        assertIssuerTrusted(createStaticIssuerAllowlist([]), validated('https://issuer.example')),
      (): void =>
        assertIssuerTrusted(registry, {
          identifier: 'https://issuer.example',
        } as unknown as ValidatedIssuer),
    ];

    const observed = refusals.map((act) => {
      try {
        act();
        return 'no-throw';
      } catch (error) {
        const domainError = error as InvalidCredentialsError;
        return `${domainError.name}|${domainError.code}|${domainError.statusCode}|${domainError.message}`;
      }
    });

    expect(new Set(observed).size).toBe(1);
    expect(observed[0]).toBe(
      `InvalidCredentialsError|INVALID_CREDENTIALS|401|${ISSUER_TRUST_REJECTION_MESSAGE}`
    );
  });

  it('carries neither the issuer nor the allowlist in the thrown error', () => {
    try {
      assertIssuerTrusted(registry, validated('https://other.example'));
      expect.unreachable('should have refused');
    } catch (error) {
      const serialized = JSON.stringify({
        message: (error as Error).message,
        ...(error as object),
      });
      expect(serialized).not.toContain('issuer.example');
      expect(serialized).not.toContain('other.example');
    }
  });

  it('refuses a backend that returns a truthy non-boolean', () => {
    const sloppy: TrustRegistry = {
      isTrusted: (): boolean => 'yes' as unknown as boolean,
    };

    expect(() => assertIssuerTrusted(sloppy, validated('https://issuer.example'))).toThrow(
      InvalidCredentialsError
    );
  });
});

describe('TrustRegistry is swappable (#236 acceptance criterion)', () => {
  /**
   * A second backend, standing in for the HAIP §6.1.1 path that ships after
   * #298: trust is decided by chain-to-anchor validation rather than by
   * membership in a list, and `x5c` resolution is mandatory.
   *
   * It exists to prove the seam: no caller of `assertIssuerTrusted` changes.
   */
  function createChainValidatingRegistry(trustAnchorSuffix: string): TrustRegistry {
    return {
      isTrusted(issuer: ValidatedIssuer): boolean {
        if (!ValidatedIssuer.isValidated(issuer)) return false;
        if (issuer.keyResolution !== 'x5c') return false;
        return new URL(issuer.identifier).hostname.endsWith(trustAnchorSuffix);
      },
    };
  }

  const anchored = createChainValidatingRegistry('.trusted-anchor.test');

  it('accepts an issuer whose chain reaches the anchor', () => {
    expect(() =>
      assertIssuerTrusted(anchored, validated('https://leaf.trusted-anchor.test', 'x5c'))
    ).not.toThrow();
  });

  it('refuses an issuer outside the anchor, through the same gate', () => {
    expect(() =>
      assertIssuerTrusted(anchored, validated('https://leaf.other-anchor.test', 'x5c'))
    ).toThrow(InvalidCredentialsError);
  });

  it('refuses metadata-resolved keys, which the base allowlist would have accepted', () => {
    // Same identifier, same gate, different backend, different answer — with no
    // change to the call site.
    const identifier = 'https://leaf.trusted-anchor.test';

    expect(() => assertIssuerTrusted(anchored, validated(identifier, 'issuer-metadata'))).toThrow(
      InvalidCredentialsError
    );
    expect(() =>
      assertIssuerTrusted(createStaticIssuerAllowlist([identifier]), validated(identifier))
    ).not.toThrow();
  });

  it('refuses a forged identity, as every backend must', () => {
    expect(
      anchored.isTrusted({
        identifier: 'https://leaf.trusted-anchor.test',
        keyResolution: 'x5c',
      } as unknown as ValidatedIssuer)
    ).toBe(false);
  });
});
