import type { FastifyInstance } from 'fastify';
import { beforeEach, describe, expect, it, vi } from 'vitest';

// The resolver pulls in `./realm`, which loads `../../config/env` (validated at
// import time). Mock it so the suite doesn't require a full env — only
// DEFAULT_REALM_NAME is read by getOrCreateDefaultRealm.
vi.mock('../../config/env', () => ({ env: { DEFAULT_REALM_NAME: 'default' } }));

import {
  REALM_TIER_CACHE_TTL_MS,
  resetRealmRateLimitTierCache,
  resolveRealmRateLimitMax,
} from './realm-rate-limit';

const CONFIG = { lenientMax: 300, strictMax: 30 } as const;

/**
 * Build a minimal FastifyInstance whose default-realm lookup returns a realm
 * with the given `maxEnvironmentLaxity`. The `findByName` spy lets tests assert
 * how often the database was consulted (cache behaviour).
 */
function fastifyWithRealmCeiling(maxEnvironmentLaxity: string | null) {
  const findByName = vi
    .fn()
    .mockResolvedValue({ id: 'realm-1', name: 'default', maxEnvironmentLaxity });
  return {
    instance: { repositories: { realms: { findByName } } } as unknown as FastifyInstance,
    findByName,
  };
}

describe('resolveRealmRateLimitMax', () => {
  beforeEach(() => {
    resetRealmRateLimitTierCache();
  });

  it('returns the strict cap when the realm ceiling is production', async () => {
    const { instance } = fastifyWithRealmCeiling('production');
    await expect(resolveRealmRateLimitMax(instance, CONFIG, 0)).resolves.toBe(CONFIG.strictMax);
  });

  it('returns the lenient cap when the realm ceiling is development', async () => {
    const { instance } = fastifyWithRealmCeiling('development');
    await expect(resolveRealmRateLimitMax(instance, CONFIG, 0)).resolves.toBe(CONFIG.lenientMax);
  });

  it('keeps strict (production-grade) limits for staging', async () => {
    // ADR-008 §5: staging shares the lenient tier (load testing), production is strict.
    const { instance } = fastifyWithRealmCeiling('staging');
    await expect(resolveRealmRateLimitMax(instance, CONFIG, 0)).resolves.toBe(CONFIG.lenientMax);
  });

  it('fails safe to the strict cap when the realm ceiling is unset/invalid', async () => {
    const { instance } = fastifyWithRealmCeiling(null);
    await expect(resolveRealmRateLimitMax(instance, CONFIG, 0)).resolves.toBe(CONFIG.strictMax);
  });

  it('fails safe to the strict cap when the realm lookup throws', async () => {
    const findByName = vi.fn().mockRejectedValue(new Error('db down'));
    const instance = { repositories: { realms: { findByName } } } as unknown as FastifyInstance;
    await expect(resolveRealmRateLimitMax(instance, CONFIG, 0)).resolves.toBe(CONFIG.strictMax);
  });

  it('caches the resolved tier within the TTL and re-reads after it expires', async () => {
    const { instance, findByName } = fastifyWithRealmCeiling('development');

    // First call reads the realm.
    expect(await resolveRealmRateLimitMax(instance, CONFIG, 0)).toBe(CONFIG.lenientMax);
    // Second call within the TTL is served from cache (no extra DB read).
    expect(await resolveRealmRateLimitMax(instance, CONFIG, REALM_TIER_CACHE_TTL_MS - 1)).toBe(
      CONFIG.lenientMax
    );
    expect(findByName).toHaveBeenCalledTimes(1);

    // Past the TTL the realm is re-read.
    expect(await resolveRealmRateLimitMax(instance, CONFIG, REALM_TIER_CACHE_TTL_MS)).toBe(
      CONFIG.lenientMax
    );
    expect(findByName).toHaveBeenCalledTimes(2);
  });
});
