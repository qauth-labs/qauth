import type { ZodType } from 'zod';

/**
 * Cache utilities interface
 */
export interface CacheUtilsInstance {
  setCache<T>(key: string, data: T, ttl?: number): Promise<void>;
  /**
   * Read a cached value. When `schema` is provided, the parsed value is
   * validated against it; a validation failure (or malformed JSON) is treated
   * as a cache MISS — the method returns `null` and logs a warning rather than
   * returning a mis-typed object or throwing.
   */
  getCache<T>(key: string, schema?: ZodType<T>): Promise<T | null>;
  deleteCache(key: string): Promise<void>;
  hasCache(key: string): Promise<boolean>;
  /**
   * Return the cached value or compute, store, and return it. When `schema` is
   * provided it validates the cached value on read; an invalid cache entry is
   * treated as a miss and the fallback recomputes the value.
   */
  getOrSetCache<T>(
    key: string,
    fallback: () => Promise<T>,
    ttl?: number,
    schema?: ZodType<T>
  ): Promise<T>;
}
