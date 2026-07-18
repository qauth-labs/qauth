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
