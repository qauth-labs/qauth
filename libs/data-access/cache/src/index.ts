// Redis connection
export * from './lib/redis';

// Utility classes and functions
export * from './lib/utils';

// Re-export commonly used items for convenience
export {
  getRedis,
  testConnection,
  isRedisConnected,
  closeRedis,
  gracefulShutdown,
  redisClient,
} from './lib/redis';

export {
  SessionUtils,
  RateLimitUtils,
  CacheUtils,
  UserUtils,
  TokenUtils,
  KEY_PREFIXES,
  DEFAULT_TTL,
} from './lib/utils';
