import { describe, expect, it } from 'vitest';

import { cryptoEnvSchema } from './crypto';

describe('cryptoEnvSchema (SIGNING_ALGORITHM_MODE)', () => {
  it('defaults to ed25519-only when unset (fail-safe: PQC opt-in)', () => {
    const parsed = cryptoEnvSchema.parse({});
    expect(parsed.SIGNING_ALGORITHM_MODE).toBe('ed25519');
    expect(parsed.enabledSignatureAlgorithms).toEqual(['EdDSA']);
  });

  it('enables both algorithms in ed25519+ml-dsa-65 mode', () => {
    const parsed = cryptoEnvSchema.parse({ SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65' });
    expect(parsed.enabledSignatureAlgorithms).toEqual(['EdDSA', 'ML-DSA-65']);
  });

  it('rejects an unknown mode at parse time', () => {
    expect(() => cryptoEnvSchema.parse({ SIGNING_ALGORITHM_MODE: 'ml-dsa-only' })).toThrow();
  });
});

describe('cryptoEnvSchema (HYBRID_SIGNING_ENABLED coupling — #245)', () => {
  const SEED = Buffer.alloc(32, 7).toString('base64url'); // a valid 32-byte seed

  it('is off by default (no ML-DSA key required)', () => {
    const parsed = cryptoEnvSchema.parse({});
    expect(parsed.HYBRID_SIGNING_ENABLED).toBe(false);
  });

  it('enabling requires ed25519+ml-dsa-65 mode (fail-fast)', () => {
    expect(() =>
      cryptoEnvSchema.parse({
        HYBRID_SIGNING_ENABLED: 'true',
        SIGNING_ALGORITHM_MODE: 'ed25519',
        JWT_MLDSA_PRIVATE_KEY: SEED,
      })
    ).toThrow(/ed25519\+ml-dsa-65/);
  });

  it('enabling requires a configured ML-DSA key (fail-fast)', () => {
    expect(() =>
      cryptoEnvSchema.parse({
        HYBRID_SIGNING_ENABLED: 'true',
        SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65',
      })
    ).toThrow(/ML-DSA key/);
  });

  it('accepts a fully-coherent hybrid configuration', () => {
    const parsed = cryptoEnvSchema.parse({
      HYBRID_SIGNING_ENABLED: 'true',
      SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65',
      JWT_MLDSA_PRIVATE_KEY: SEED,
      JWT_MLDSA_KID: 'k1-mldsa',
    });
    expect(parsed.HYBRID_SIGNING_ENABLED).toBe(true);
    expect(parsed.JWT_MLDSA_PRIVATE_KEY).toBe(SEED);
    expect(parsed.JWT_MLDSA_KID).toBe('k1-mldsa');
  });
});
