import { describe, expect, it } from 'vitest';

import { federationEnvSchema } from './federation';

describe('federationEnvSchema (WALLET_FEDERATION_ENABLED — #232)', () => {
  it('is off by default when unset (epic #231 is incomplete)', () => {
    expect(federationEnvSchema.parse({}).WALLET_FEDERATION_ENABLED).toBe(false);
  });

  it.each([
    ['true', true],
    ['1', true],
    ['false', false],
    ['0', false],
  ])('coerces %s to %s', (raw, expected) => {
    expect(
      federationEnvSchema.parse({ WALLET_FEDERATION_ENABLED: raw }).WALLET_FEDERATION_ENABLED
    ).toBe(expected);
  });

  it.each(['yes', 'TRUE', 'on', ''])(
    'rejects the unrecognized value %o at parse time (never silently truthy)',
    (raw) => {
      expect(() => federationEnvSchema.parse({ WALLET_FEDERATION_ENABLED: raw })).toThrow();
    }
  );

  it('exposes a plain object shape so auth-server can spread it into its env schema', () => {
    // A `.superRefine()`/`.transform()`-wrapped schema has no `.shape`, which
    // would break `z.object({ ...federationEnvSchema.shape })` in env.ts.
    expect(Object.keys(federationEnvSchema.shape)).toEqual(['WALLET_FEDERATION_ENABLED']);
  });
});
