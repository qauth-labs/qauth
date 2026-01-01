/**
 * Cache utilities interface
 */
export interface CacheUtilsInstance {
  setCache<T>(key: string, data: T, ttl?: number): Promise<void>;
  getCache<T>(key: string): Promise<T | null>;
  deleteCache(key: string): Promise<void>;
  hasCache(key: string): Promise<boolean>;
  getOrSetCache<T>(key: string, fallback: () => Promise<T>, ttl?: number): Promise<T>;
}
