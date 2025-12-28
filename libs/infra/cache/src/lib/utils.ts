import { getRedis } from './redis';

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
 * Session data type - can be extended by consumers
 */
export interface SessionData {
  [key: string]: unknown;
}

/**
 * Session storage utilities
 */
export class SessionUtils {
  /**
   * Set session data
   */
  static async setSession<T extends SessionData>(
    sessionId: string,
    data: T,
    ttl: number = DEFAULT_TTL.SESSION
  ): Promise<void> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
    await client.setex(key, ttl, JSON.stringify(data));
  }

  /**
   * Get session data
   */
  static async getSession<T extends SessionData>(sessionId: string): Promise<T | null> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
    const data = await client.get(key);
    return data ? (JSON.parse(data) as T) : null;
  }

  /**
   * Delete session
   */
  static async deleteSession(sessionId: string): Promise<void> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
    await client.del(key);
  }

  /**
   * Extend session TTL
   */
  static async extendSession(sessionId: string, ttl: number = DEFAULT_TTL.SESSION): Promise<void> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
    await client.expire(key, ttl);
  }

  /**
   * Check if session exists
   */
  static async hasSession(sessionId: string): Promise<boolean> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.SESSION}${sessionId}`;
    return (await client.exists(key)) === 1;
  }
}

/**
 * Rate limiting utilities
 */
export class RateLimitUtils {
  /**
   * Check rate limit
   */
  static async checkRateLimit(
    key: string,
    limit: number,
    windowSeconds = 60
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    const client = getRedis();
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
  }

  /**
   * Reset rate limit counter
   */
  static async resetRateLimit(key: string): Promise<void> {
    const client = getRedis();
    const rateKey = `${KEY_PREFIXES.RATE_LIMIT}${key}`;
    await client.del(rateKey);
  }

  /**
   * Get rate limit status
   */
  static async getRateLimitStatus(
    key: string,
    limit: number
  ): Promise<{ current: number; remaining: number; resetTime: number }> {
    const client = getRedis();
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
  }
}

/**
 * Cache utilities
 */
export class CacheUtils {
  /**
   * Set cache data
   */
  static async setCache<T>(key: string, data: T, ttl: number = DEFAULT_TTL.CACHE): Promise<void> {
    const client = getRedis();
    const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
    await client.setex(cacheKey, ttl, JSON.stringify(data));
  }

  /**
   * Get cache data
   */
  static async getCache<T>(key: string): Promise<T | null> {
    const client = getRedis();
    const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
    const data = await client.get(cacheKey);
    return data ? (JSON.parse(data) as T) : null;
  }

  /**
   * Delete cache
   */
  static async deleteCache(key: string): Promise<void> {
    const client = getRedis();
    const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
    await client.del(cacheKey);
  }

  /**
   * Check if cache exists
   */
  static async hasCache(key: string): Promise<boolean> {
    const client = getRedis();
    const cacheKey = `${KEY_PREFIXES.CACHE}${key}`;
    return (await client.exists(cacheKey)) === 1;
  }

  /**
   * Get or set cache with fallback function
   */
  static async getOrSetCache<T>(
    key: string,
    fallback: () => Promise<T>,
    ttl: number = DEFAULT_TTL.CACHE
  ): Promise<T> {
    const cached = await this.getCache<T>(key);
    if (cached !== null) {
      return cached;
    }

    const data = await fallback();
    await this.setCache(key, data, ttl);
    return data;
  }
}

/**
 * User data type - can be extended by consumers
 */
export interface UserData {
  [key: string]: unknown;
}

/**
 * User data utilities
 */
export class UserUtils {
  /**
   * Set user data
   */
  static async setUserData<T extends UserData>(
    userId: string,
    data: T,
    ttl: number = DEFAULT_TTL.USER
  ): Promise<void> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.USER}${userId}`;
    await client.setex(key, ttl, JSON.stringify(data));
  }

  /**
   * Get user data
   */
  static async getUserData<T extends UserData>(userId: string): Promise<T | null> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.USER}${userId}`;
    const data = await client.get(key);
    return data ? (JSON.parse(data) as T) : null;
  }

  /**
   * Delete user data
   */
  static async deleteUserData(userId: string): Promise<void> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.USER}${userId}`;
    await client.del(key);
  }
}

/**
 * Token utilities
 */
export class TokenUtils {
  /**
   * Blacklist token
   */
  static async blacklistToken(token: string, ttl: number = DEFAULT_TTL.TOKEN): Promise<void> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.TOKEN}blacklist:${token}`;
    await client.setex(key, ttl, '1');
  }

  /**
   * Check if token is blacklisted
   */
  static async isTokenBlacklisted(token: string): Promise<boolean> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.TOKEN}blacklist:${token}`;
    return (await client.exists(key)) === 1;
  }

  /**
   * Remove token from blacklist
   */
  static async unblacklistToken(token: string): Promise<void> {
    const client = getRedis();
    const key = `${KEY_PREFIXES.TOKEN}blacklist:${token}`;
    await client.del(key);
  }
}
