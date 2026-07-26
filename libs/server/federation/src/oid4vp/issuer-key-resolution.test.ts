import { describe, expect, it } from 'vitest';

import { createStaticIssuerKeyResolver } from './issuer-key-resolution';
import { generateFixtureKeys, TEST_ISSUER } from './sd-jwt-vc.fixture';

describe('createStaticIssuerKeyResolver — configuration', () => {
  it('refuses an issuer identifier that is not an https URL', async () => {
    const keys = await generateFixtureKeys();

    expect(() =>
      createStaticIssuerKeyResolver([{ issuer: 'http://issuer.example.com', jwks: [keys.jwk] }])
    ).toThrow(/not a usable issuer identity/);
  });

  it('refuses an issuer configured with no keys', () => {
    expect(() => createStaticIssuerKeyResolver([{ issuer: TEST_ISSUER, jwks: [] }])).toThrow(
      /is empty/
    );
  });

  it('refuses the same issuer configured twice', async () => {
    const keys = await generateFixtureKeys();

    expect(() =>
      createStaticIssuerKeyResolver([
        { issuer: TEST_ISSUER, jwks: [keys.jwk] },
        { issuer: `${TEST_ISSUER}/`, jwks: [keys.jwk] },
      ])
    ).toThrow(/configured twice/);
  });
});

describe('createStaticIssuerKeyResolver — resolution', () => {
  it('resolves a configured issuer and reports how the key was obtained', async () => {
    const keys = await generateFixtureKeys();
    const resolve = createStaticIssuerKeyResolver([{ issuer: TEST_ISSUER, jwks: [keys.jwk] }]);

    const resolved = await resolve({ issuer: TEST_ISSUER, algorithm: 'ES256' });

    expect(resolved?.identifier).toBe(TEST_ISSUER);
    expect(resolved?.keyResolution).toBe('issuer-metadata');
    expect(resolved?.key.type).toBe('public');
  });

  it('canonicalizes both sides of the lookup', async () => {
    const keys = await generateFixtureKeys();
    const resolve = createStaticIssuerKeyResolver([
      { issuer: 'https://Issuer.Example.com/tenant/', jwks: [keys.jwk] },
    ]);

    const resolved = await resolve({
      issuer: 'https://issuer.example.com:443/tenant',
      algorithm: 'ES256',
    });

    expect(resolved?.identifier).toBe('https://issuer.example.com/tenant');
  });

  it('resolves nothing for an unconfigured issuer', async () => {
    const keys = await generateFixtureKeys();
    const resolve = createStaticIssuerKeyResolver([{ issuer: TEST_ISSUER, jwks: [keys.jwk] }]);

    await expect(
      resolve({ issuer: 'https://other-issuer.example.net', algorithm: 'ES256' })
    ).resolves.toBeUndefined();
  });

  it('resolves nothing for an issuer identifier that does not canonicalize', async () => {
    const keys = await generateFixtureKeys();
    const resolve = createStaticIssuerKeyResolver([{ issuer: TEST_ISSUER, jwks: [keys.jwk] }]);

    await expect(resolve({ issuer: 'not a url', algorithm: 'ES256' })).resolves.toBeUndefined();
  });

  it('selects by kid', async () => {
    const first = await generateFixtureKeys('ES256', 'key-1');
    const second = await generateFixtureKeys('ES256', 'key-2');
    const resolve = createStaticIssuerKeyResolver([
      { issuer: TEST_ISSUER, jwks: [first.jwk, second.jwk] },
    ]);

    const resolved = await resolve({ issuer: TEST_ISSUER, keyId: 'key-2', algorithm: 'ES256' });

    expect(resolved).toBeDefined();
  });

  it('does NOT fall back to another key when the kid names none', async () => {
    const keys = await generateFixtureKeys('ES256', 'key-1');
    const resolve = createStaticIssuerKeyResolver([{ issuer: TEST_ISSUER, jwks: [keys.jwk] }]);

    // A fallback would make `kid` a hint an attacker can drop to widen the set
    // of keys their credential is checked against.
    await expect(
      resolve({ issuer: TEST_ISSUER, keyId: 'key-does-not-exist', algorithm: 'ES256' })
    ).resolves.toBeUndefined();
  });

  it('refuses to guess when several keys are configured and no kid is given', async () => {
    const first = await generateFixtureKeys('ES256', 'key-1');
    const second = await generateFixtureKeys('ES256', 'key-2');
    const resolve = createStaticIssuerKeyResolver([
      { issuer: TEST_ISSUER, jwks: [first.jwk, second.jwk] },
    ]);

    await expect(resolve({ issuer: TEST_ISSUER, algorithm: 'ES256' })).resolves.toBeUndefined();
  });

  it('refuses a key that does not match the pinned algorithm', async () => {
    const keys = await generateFixtureKeys('EdDSA');
    const resolve = createStaticIssuerKeyResolver([{ issuer: TEST_ISSUER, jwks: [keys.jwk] }]);

    // The caller's algorithm is policy; the JWK is untrusted input. A mismatch
    // resolves nothing rather than importing the key for a primitive its
    // publisher did not intend.
    await expect(resolve({ issuer: TEST_ISSUER, algorithm: 'ES256' })).resolves.toBeUndefined();
  });

  it('refuses a JWK carrying private key material', async () => {
    const resolve = createStaticIssuerKeyResolver([
      {
        issuer: TEST_ISSUER,
        jwks: [{ kty: 'EC', crv: 'P-256', x: 'AA', y: 'BB', d: 'secret' }],
      },
    ]);

    await expect(resolve({ issuer: TEST_ISSUER, algorithm: 'ES256' })).resolves.toBeUndefined();
  });

  it('never claims the x5c resolution it does not perform', async () => {
    const keys = await generateFixtureKeys();
    const resolve = createStaticIssuerKeyResolver([{ issuer: TEST_ISSUER, jwks: [keys.jwk] }]);

    // A credential may carry an `x5c` chain; THIS backend resolves keys from
    // configured metadata and must say so, whatever the credential presents.
    // Chain validation to an operator-provisioned anchor (HAIP §6.1.1) is a
    // different implementation of the same port — see the sd-jwt-vc suite.
    const resolved = await resolve({
      issuer: TEST_ISSUER,
      algorithm: 'ES256',
      x5c: ['MIIBleaf', 'MIIBca'],
    });

    expect(resolved?.keyResolution).toBe('issuer-metadata');
  });
});
