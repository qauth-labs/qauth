import type { FastifyInstance } from 'fastify';

import {
  ENVIRONMENT_PROFILES,
  parseEnvironment,
  type RateLimitTier,
  type RateLimitTierConfig,
  resolveRateLimitMax,
} from './environment-policy';
import { getOrCreateDefaultRealm } from './realm';

/**
 * How long a resolved realm rate-limit tier is cached in-process before the
 * default realm's `max_environment_laxity` is re-read.
 *
 * `@fastify/rate-limit` evaluates the `max` callback on EVERY request to a
 * rate-limited route, so reading the realm from the database each time would
 * add a round-trip to hot OAuth endpoints (`/oauth/token`, `/oauth/authorize`).
 * A short TTL keeps the cost negligible while still picking up an operator's
 * ceiling change within seconds. Module-scoped because the default realm is
 * process-wide.
 */
export const REALM_TIER_CACHE_TTL_MS = 30_000;

let cachedTier: { tier: RateLimitTier; expiresAt: number } | null = null;

/** Test-only: clear the in-process realm tier cache. */
export function resetRealmRateLimitTierCache(): void {
  cachedTier = null;
}

/**
 * Resolve the per-window request cap for a rate-limited route from the default
 * realm's environment ceiling (ADR-008 §5, issue #209).
 *
 * `@fastify/rate-limit` evaluates `max` BEFORE the route handler runs — i.e.
 * before the specific client is authenticated — so a per-client policy is not
 * available here. The honest seam is realm-level: a `production` realm forces
 * the strict cap regardless of any client, while a `development` / `staging`
 * realm ceiling permits the lenient cap (e.g. for load testing).
 *
 * Fail-safe: any error (database unavailable, etc.) returns the strict cap, so
 * a misconfiguration or outage never relaxes the limit.
 *
 * @param now Injectable clock (milliseconds) for deterministic tests; defaults
 * to the wall clock.
 */
export async function resolveRealmRateLimitMax(
  fastify: FastifyInstance,
  config: RateLimitTierConfig,
  now: number = Date.now()
): Promise<number> {
  try {
    if (!cachedTier || now >= cachedTier.expiresAt) {
      const realm = await getOrCreateDefaultRealm(fastify);
      const environment = parseEnvironment(realm.maxEnvironmentLaxity);
      const tier = ENVIRONMENT_PROFILES[environment].rateLimitTier;
      cachedTier = { tier, expiresAt: now + REALM_TIER_CACHE_TTL_MS };
    }
    return resolveRateLimitMax(cachedTier.tier, config);
  } catch {
    return config.strictMax;
  }
}
