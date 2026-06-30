import type { ZodType } from 'zod';

import type {
  CacheClient,
  CacheUtilsInstance,
  Logger,
  RateLimitResult,
  RateLimitStatus,
  RateLimitUtilsInstance,
  SessionData,
  SessionUtilsInstance,
  TokenUtilsInstance,
  UserData,
  UserUtilsInstance,
} from '../types';

export type {
  CacheUtilsInstance,
  Logger,
  RateLimitResult,
  RateLimitStatus,
  RateLimitUtilsInstance,
  SessionData,
  SessionUtilsInstance,
  TokenUtilsInstance,
  UserData,
  UserUtilsInstance,
};

/**
 * Safely deserialize a raw cache string into a typed value.
 *
 * Without a schema this preserves the historical behaviour (`JSON.parse` cast
 * to `T`) but no longer lets a malformed JSON string throw an uncaught error:
 * a parse failure is treated as a cache MISS (returns `null`) and logged.
 *
 * With a schema the parsed value is validated; on failure the entry is treated
 * as a cache MISS so corrupted or attacker-injected values can never surface as
 * a wrong-shaped object.
 *
 * @param raw - Raw string read from the cache (or `null` for a miss)
 * @param key - Cache key, used only for diagnostic logging
 * @param logger - Logger used to warn on malformed/invalid entries
 * @param schema - Optional Zod schema to validate the parsed value
 * @returns The typed value, or `null` on a miss/parse/validation failure
 */
function parseCached<T>(
  raw: string | null,
  key: string,
  logger: Logger,
  schema?: ZodType<T>
): T | null {
  if (raw === null) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    logger.warn(`Cache: malformed JSON for key "${key}", treating as miss`, error);
    return null;
  }

  if (!schema) {
    return parsed as T;
  }

  const result = schema.safeParse(parsed);
  if (!result.success) {
    logger.warn(
      `Cache: value for key "${key}" failed schema validation, treating as miss`,
      result.error.issues
    );
    return null;
  }

  return result.data;
}

/**
 * Key prefixes for different data types
 */
export const KEY_PREFIXES = {
  SESSION: 'session:',
  RATE_LIMIT: 'rate:',
  CACHE: 'cache:',
  USER: 'user:',
  TOKEN: 'token:',
} as const;

/**
 * Default TTL values in seconds
 */
export const DEFAULT_TTL = {
  SESSION: 24 * 60 * 60, // 24 hours
  RATE_LIMIT: 60, // 1 minute
  CACHE: 5 * 60, // 5 minutes
  USER: 30 * 60, // 30 minutes
  TOKEN: 15 * 60, // 15 minutes
} as const;

/**
 * Create session utilities with the given Redis client
 *
 * @param client - Redis client instance
 * @param logger - Optional logger for diagnostics (defaults to `console`)
 * @returns Session utilities object
 */
export function createSessionUtils(
  client: CacheClient,
  logger: Logger = console
): SessionUtilsInstance {
  return {
    async setSession<T extends SessionData>(
      sessionId: string,
      data: T,
      ttl: number = DEFAULT_TTL.SESSION
    ): Promise<void> {
      const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
      await client.setex(key, ttl, JSON.stringify(data));
    },

    async getSession<T extends SessionData>(
      sessionId: string,
      schema?: ZodType<T>
    ): Promise<T | null> {
      const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
      const data = await client.get(key);
      return parseCached(data, key, logger, schema);
    },

    async deleteSession(sessionId: string): Promise<void> {
      const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
      await client.del(key);
    },

    async extendSession(sessionId: string, ttl: number = DEFAULT_TTL.SESSION): Promise<void> {
      const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
      await client.expire(key, ttl);
    },

    async hasSession(sessionId: string): Promise<boolean> {
      const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
      return (await client.exists(key)) === 1;
    },
  };
}

/**
 * Create rate limiting utilities with the given Redis client
 *
 * @param client - Redis client instance
 * @returns Rate limit utilities object
 */
export function createRateLimitUtils(client: CacheClient): RateLimitUtilsInstance {
  return {
    async checkRateLimit(key: string, limit: number, windowSeconds = 60): Promise<RateLimitResult> {
      const rateKey = `${KEY_PREFIXES.RATE_LIMIT}${key}`;

      const current = await client.incr(rateKey);

      if (current === 1) {
        await client.expire(rateKey, windowSeconds);
      }

      const ttl = await client.ttl(rateKey);
      const resetTime = Date.now() + ttl * 1000;

      return {
        allowed: current <= limit,
        remaining: Math.max(0, limit - current),
        resetTime,
      };
    },

    async resetRateLimit(key: string): Promise<void> {
      const rateKey = `${KEY_PREFIXES.RATE_LIMIT}${key}`;
      await client.del(rateKey);
    },

    async getRateLimitStatus(key: string, limit: number): Promise<RateLimitStatus> {
      const rateKey = `${KEY_PREFIXES.RATE_LIMIT}${key}`;

      const current = await client.get(rateKey);
      const count = current ? parseInt(current, 10) : 0;
      const ttl = await client.ttl(rateKey);
      const resetTime = ttl > 0 ? Date.now() + ttl * 1000 : 0;

      return {
        current: count,
        remaining: Math.max(0, limit - count),
        resetTime,
      };
    },
  };
}

/**
 * Create cache utilities with the given Redis client
 *
 * @param client - Redis client instance
 * @param logger - Optional logger for diagnostics (defaults to `console`)
 * @returns Cache utilities object
 */
export function createCacheUtils(
  client: CacheClient,
  logger: Logger = console
): CacheUtilsInstance {
  const utils: CacheUtilsInstance = {
    async setCache<T>(key: string, data: T, ttl: number = DEFAULT_TTL.CACHE): Promise<void> {
      const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
      await client.setex(cacheKey, ttl, JSON.stringify(data));
    },

    async getCache<T>(key: string, schema?: ZodType<T>): Promise<T | null> {
      const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
      const data = await client.get(cacheKey);
      return parseCached(data, cacheKey, logger, schema);
    },

    async deleteCache(key: string): Promise<void> {
      const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
      await client.del(cacheKey);
    },

    async hasCache(key: string): Promise<boolean> {
      const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
      return (await client.exists(cacheKey)) === 1;
    },

    async getOrSetCache<T>(
      key: string,
      fallback: () => Promise<T>,
      ttl: number = DEFAULT_TTL.CACHE,
      schema?: ZodType<T>
    ): Promise<T> {
      const cached = await utils.getCache<T>(key, schema);
      if (cached !== null) {
        return cached;
      }

      const data = await fallback();
      await utils.setCache(key, data, ttl);
      return data;
    },
  };

  return utils;
}

/**
 * Create user data utilities with the given Redis client
 *
 * @param client - Redis client instance
 * @param logger - Optional logger for diagnostics (defaults to `console`)
 * @returns User utilities object
 */
export function createUserUtils(client: CacheClient, logger: Logger = console): UserUtilsInstance {
  return {
    async setUserData<T extends UserData>(
      userId: string,
      data: T,
      ttl: number = DEFAULT_TTL.USER
    ): Promise<void> {
      const key = `${KEY_PREFIXES.USER}${userId}`;
      await client.setex(key, ttl, JSON.stringify(data));
    },

    async getUserData<T extends UserData>(userId: string, schema?: ZodType<T>): Promise<T | null> {
      const key = `${KEY_PREFIXES.USER}${userId}`;
      const data = await client.get(key);
      return parseCached(data, key, logger, schema);
    },

    async deleteUserData(userId: string): Promise<void> {
      const key = `${KEY_PREFIXES.USER}${userId}`;
      await client.del(key);
    },
  };
}

/**
 * Create token utilities with the given Redis client
 *
 * @param client - Redis client instance
 * @returns Token utilities object
 */
export function createTokenUtils(client: CacheClient): TokenUtilsInstance {
  return {
    async blacklistToken(token: string, ttl: number = DEFAULT_TTL.TOKEN): Promise<void> {
      const key = `${KEY_PREFIXES.TOKEN}blacklist:${token}`;
      await client.setex(key, ttl, '1');
    },

    async isTokenBlacklisted(token: string): Promise<boolean> {
      const key = `${KEY_PREFIXES.TOKEN}blacklist:${token}`;
      return (await client.exists(key)) === 1;
    },

    async unblacklistToken(token: string): Promise<void> {
      const key = `${KEY_PREFIXES.TOKEN}blacklist:${token}`;
      await client.del(key);
    },
  };
}
