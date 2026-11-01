import { describe, expect, it } from 'vitest';

import {
  jwtEnvSchema,
  MAX_ACCESS_TOKEN_LIFESPAN_SECONDS,
  MAX_REFRESH_TOKEN_LIFESPAN_SECONDS,
} from './jwt';

const BASE = { JWT_ISSUER: 'https://auth.example.com' };

/** The paths of the variables `env` is refused for, or `[]` when it parses. */
function refusedPaths(env: Record<string, string>): string[] {
  const result = jwtEnvSchema.safeParse({ ...BASE, ...env });
  return result.success ? [] : result.error.issues.map((issue) => issue.path.join('.'));
}

describe('jwtEnvSchema token lifetimes', () => {
  it('bounds an access token at a day and a refresh token at 90 days', () => {
    expect(MAX_ACCESS_TOKEN_LIFESPAN_SECONDS).toBe(86_400);
    expect(MAX_REFRESH_TOKEN_LIFESPAN_SECONDS).toBe(7_776_000);
  });

  // A token must verify for its whole life, and a retired signing key leaves
  // the verification set when its retention ends: 14 days,
  // DEFAULT_KEY_RETIRED_RETENTION_DAYS of @qauth-labs/server-keys, which its
  // own test pins. The longest access (and ID) token stays well inside it.
  it('keeps the longest access token inside the retired-key retention', () => {
    expect(MAX_ACCESS_TOKEN_LIFESPAN_SECONDS).toBeLessThan(14 * 86_400);
  });

  it('accepts each lifetime at its bound', () => {
    expect(
      refusedPaths({
        ACCESS_TOKEN_LIFESPAN: '86400',
        DEV_ACCESS_TOKEN_LIFESPAN: '86400',
        REFRESH_TOKEN_LIFESPAN: '7776000',
      })
    ).toEqual([]);
  });

  it('refuses each lifetime above its bound', () => {
    expect(refusedPaths({ ACCESS_TOKEN_LIFESPAN: '86401' })).toEqual(['ACCESS_TOKEN_LIFESPAN']);
    expect(refusedPaths({ DEV_ACCESS_TOKEN_LIFESPAN: '86401' })).toEqual([
      'DEV_ACCESS_TOKEN_LIFESPAN',
    ]);
    expect(refusedPaths({ REFRESH_TOKEN_LIFESPAN: '7776001' })).toEqual(['REFRESH_TOKEN_LIFESPAN']);
  });
});
