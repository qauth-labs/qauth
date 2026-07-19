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

describe('cryptoEnvSchema (ML-DSA seed validation — #248 F8)', () => {
  const VALID_SEED = Buffer.alloc(32, 7).toString('base64url');
  const HYBRID_ON = {
    HYBRID_SIGNING_ENABLED: 'true',
    SIGNING_ALGORITHM_MODE: 'ed25519+ml-dsa-65',
  } as const;

  it('accepts a base64url seed that decodes to exactly 32 bytes', () => {
    const parsed = cryptoEnvSchema.parse({ ...HYBRID_ON, JWT_MLDSA_PRIVATE_KEY: VALID_SEED });
    expect(parsed.JWT_MLDSA_PRIVATE_KEY).toBe(VALID_SEED);
  });

  it('rejects a seed that decodes to fewer than 32 bytes (truncated key)', () => {
    expect(() =>
      cryptoEnvSchema.parse({
        ...HYBRID_ON,
        JWT_MLDSA_PRIVATE_KEY: Buffer.alloc(31, 7).toString('base64url'),
      })
    ).toThrow(/decodes to 31 bytes, expected exactly 32/);
  });

  it('rejects a seed that decodes to more than 32 bytes', () => {
    expect(() =>
      cryptoEnvSchema.parse({
        ...HYBRID_ON,
        JWT_MLDSA_PRIVATE_KEY: Buffer.alloc(64, 7).toString('base64url'),
      })
    ).toThrow(/decodes to 64 bytes, expected exactly 32/);
  });

  it('rejects standard base64 (+ / =) — base64url is the required encoding', () => {
    // `Buffer.from(_, 'base64url')` would happily decode this to ~32 bytes, so
    // the alphabet has to be checked explicitly or the length check is a lie.
    const standardBase64 = Buffer.alloc(32, 251).toString('base64');
    expect(standardBase64).toMatch(/[+/=]/);
    expect(() =>
      cryptoEnvSchema.parse({ ...HYBRID_ON, JWT_MLDSA_PRIVATE_KEY: standardBase64 })
    ).toThrow(/not unpadded base64url/);
  });

  it('rejects a seed containing characters outside the base64url alphabet', () => {
    expect(() =>
      cryptoEnvSchema.parse({ ...HYBRID_ON, JWT_MLDSA_PRIVATE_KEY: `${VALID_SEED.slice(0, -2)}!!` })
    ).toThrow(/not unpadded base64url/);
  });

  it('validates a CONFIGURED seed even while hybrid signing is still off', () => {
    // Staging the key before flipping the flag must surface a bad seed now,
    // not at the moment PQC signing is enabled in production.
    expect(() =>
      cryptoEnvSchema.parse({ JWT_MLDSA_PRIVATE_KEY: Buffer.alloc(16, 7).toString('base64url') })
    ).toThrow(/expected exactly 32/);
  });

  it('stays silent when no seed is configured at all', () => {
    expect(() => cryptoEnvSchema.parse({})).not.toThrow();
  });

  it('never echoes the seed value into the error message', () => {
    const badSeed = Buffer.alloc(31, 9).toString('base64url');
    const error = (() => {
      try {
        cryptoEnvSchema.parse({ ...HYBRID_ON, JWT_MLDSA_PRIVATE_KEY: badSeed });
        return null;
      } catch (e: unknown) {
        return e as Error;
      }
    })();
    expect(error).not.toBeNull();
    expect(error?.message).not.toContain(badSeed);
  });

  it('reports the PATH field when the bad seed came from a file', async () => {
    const { mkdtemp, writeFile } = await import('node:fs/promises');
    const { join } = await import('node:path');
    const { tmpdir } = await import('node:os');
    const dir = await mkdtemp(join(tmpdir(), 'qauth-mldsa-'));
    const file = join(dir, 'seed');
    await writeFile(file, Buffer.alloc(8, 3).toString('base64url'), 'utf-8');

    const error = (() => {
      try {
        cryptoEnvSchema.parse({ ...HYBRID_ON, JWT_MLDSA_PRIVATE_KEY_PATH: file });
        return null;
      } catch (e: unknown) {
        return e as Error;
      }
    })();
    expect(error?.message).toContain('JWT_MLDSA_PRIVATE_KEY_PATH');
  });
});
