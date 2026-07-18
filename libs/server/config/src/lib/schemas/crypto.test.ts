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

describe('cryptoEnvSchema (PQC_TOKEN_DELIVERY posture — #247)', () => {
  const SEED = Buffer.alloc(32, 7).toString('base64url');
  const hybridBase = {
    HYBRID_SIGNING_ENABLED: 'true' as const,
    SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65' as const,
    JWT_MLDSA_PRIVATE_KEY: SEED,
  };

  it("defaults to 'reference' (introspection-first, size-safe)", () => {
    expect(cryptoEnvSchema.parse({}).PQC_TOKEN_DELIVERY).toBe('reference');
    expect(cryptoEnvSchema.parse(hybridBase).PQC_TOKEN_DELIVERY).toBe('reference');
  });

  it('rejects self-contained delivery without an explicit size acknowledgement (fail-fast)', () => {
    expect(() =>
      cryptoEnvSchema.parse({ ...hybridBase, PQC_TOKEN_DELIVERY: 'self-contained' })
    ).toThrow(/PQC_SELF_CONTAINED_ACK/);
  });

  it('accepts self-contained delivery once the size risk is acknowledged', () => {
    const parsed = cryptoEnvSchema.parse({
      ...hybridBase,
      PQC_TOKEN_DELIVERY: 'self-contained',
      PQC_SELF_CONTAINED_ACK: 'true',
    });
    expect(parsed.PQC_TOKEN_DELIVERY).toBe('self-contained');
  });

  it('does not gate self-contained delivery when hybrid signing is off', () => {
    // Classical tokens are already small self-contained JWTs; the guard only
    // applies once hybrid is enabled, so the ack is not required here.
    const parsed = cryptoEnvSchema.parse({ PQC_TOKEN_DELIVERY: 'self-contained' });
    expect(parsed.PQC_TOKEN_DELIVERY).toBe('self-contained');
  });
});
