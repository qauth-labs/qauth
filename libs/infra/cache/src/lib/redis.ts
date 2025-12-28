import Redis, { RedisOptions } from 'ioredis';

/**
 * Cache client type - abstracted from implementation
 * Currently uses ioredis Redis, but can be replaced with other cache implementations
 */
export type CacheClient = Redis;

/**
 * Redis connection configuration interface
 */
export interface RedisConfig {
  /**
   * Redis connection URL (takes precedence over individual settings)
   */
  url?: string;

  /**
   * Redis host address (used if url is not set)
   */
  host?: string;

  /**
   * Redis port number (used if url is not set)
   * @default 6379
   */
  port?: number;

  /**
   * Redis password
   */
  password?: string;

  /**
   * Redis database number
   * @default 0
   */
  db?: number;

  /**
   * Maximum retries per request
   * @default 3
   */
  maxRetriesPerRequest?: number;

  /**
   * Connection timeout in milliseconds
   * @default 10000
   */
  connectTimeout?: number;

  /**
   * Command timeout in milliseconds
   * @default 5000
   */
  commandTimeout?: number;

  /**
   * Whether to use lazy connection (connect on first command)
   * @default true
   */
  lazyConnect?: boolean;
}

/**
 * Default Redis configuration values
 */
export const DEFAULT_REDIS_CONFIG: Partial<RedisConfig> = {
  host: 'localhost',
  port: 6379,
  db: 0,
  maxRetriesPerRequest: 3,
  connectTimeout: 10000,
  commandTimeout: 5000,
  lazyConnect: true,
};

/**
 * Create a new Redis connection instance with the given configuration
 *
 * @param config - Redis configuration with connection settings
 * @returns Redis client instance
 *
 * @example
 * ```typescript
 * const redis = createRedisConnection({
 *   url: 'redis://localhost:6379/0',
 *   lazyConnect: true,
 * });
 *
 * // Or with individual settings
 * const redis = createRedisConnection({
 *   host: 'localhost',
 *   port: 6379,
 *   password: 'secret',
 *   db: 0,
 * });
 *
 * // Use the client
 * await redis.set('key', 'value');
 * const value = await redis.get('key');
 *
 * // Close when done
 * await redis.quit();
 * ```
 */
export function createRedisConnection(config: RedisConfig): CacheClient {
  // Merge with defaults (url takes precedence if provided)
  const mergedConfig: RedisConfig = {
    ...DEFAULT_REDIS_CONFIG,
    ...config,
  };

  // Build ioredis options
  const redisOptions: RedisOptions = {};

  // If URL is provided, use it
  if (mergedConfig.url) {
    // ioredis accepts URL as the first argument to constructor
    // We'll pass it through the options
    Object.assign(redisOptions, {
      host: undefined,
      port: undefined,
    });
  } else {
    // Use individual connection settings
    redisOptions.host = mergedConfig.host;
    redisOptions.port = mergedConfig.port;
    if (mergedConfig.password) {
      redisOptions.password = mergedConfig.password;
    }
    redisOptions.db = mergedConfig.db;
  }

  // Connection settings
  redisOptions.maxRetriesPerRequest = mergedConfig.maxRetriesPerRequest;
  redisOptions.connectTimeout = mergedConfig.connectTimeout;
  redisOptions.commandTimeout = mergedConfig.commandTimeout;
  redisOptions.lazyConnect = mergedConfig.lazyConnect;

  // Create Redis instance
  const redis = mergedConfig.url
    ? new Redis(mergedConfig.url, redisOptions)
    : new Redis(redisOptions);

  // Connection event handlers for logging
  redis.on('connect', () => {
    console.log('Redis: Connected');
  });

  redis.on('ready', () => {
    console.log('Redis: Ready to accept commands');
  });

  redis.on('error', (error) => {
    console.error('Redis: Connection error:', error);
  });

  redis.on('close', () => {
    console.log('Redis: Connection closed');
  });

  redis.on('reconnecting', () => {
    console.log('Redis: Reconnecting...');
  });

  redis.on('end', () => {
    console.log('Redis: Connection ended');
  });

  return redis;
}

/**
 * Test Redis connection
 *
 * @param redis - Redis client instance to test
 * @returns true if connection is successful, false otherwise
 */
export async function testRedisConnection(redis: CacheClient): Promise<boolean> {
  try {
    // Connect if not already connected (lazyConnect: true)
    if (redis.status === 'wait') {
      await redis.connect();
    }
    await redis.ping();
    return true;
  } catch (error) {
    console.error('Redis connection test failed:', error);
    return false;
  }
}

/**
 * Check if Redis is connected
 *
 * @param redis - Redis client instance to check
 * @returns true if connected and ready, false otherwise
 */
export function isRedisConnected(redis: CacheClient): boolean {
  return redis.status === 'ready';
}

/**
 * Close Redis connection
 *
 * @param redis - Redis client instance to close
 */
export async function closeRedis(redis: CacheClient): Promise<void> {
  await redis.quit();
}
