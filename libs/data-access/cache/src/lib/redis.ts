import Redis, { RedisOptions } from 'ioredis';

/**
 * Redis connection configuration interface
 */
export interface RedisConfig {
  url?: string;
  host?: string;
  port?: number;
  password?: string;
  db?: number;
  maxRetriesPerRequest?: number;
  retryDelayOnFailover?: number;
  connectTimeout?: number;
  commandTimeout?: number;
  lazyConnect?: boolean;
}

/**
 * Redis connection instance
 */
let redis: Redis | null = null;

/**
 * Redis connection status
 */
let isConnected = false;

/**
 * Get Redis configuration from environment variables
 */
function getRedisConfig(): RedisConfig {
  const config: RedisConfig = {};

  // Primary configuration: REDIS_URL
  if (process.env['REDIS_URL']) {
    config.url = process.env['REDIS_URL'];
  } else {
    // Fallback to individual configuration
    config.host = process.env['REDIS_HOST'] || 'localhost';
    config.port = parseInt(process.env['REDIS_PORT'] || '6379');
    config.password = process.env['REDIS_PASSWORD'];
    config.db = parseInt(process.env['REDIS_DB'] || '0');
  }

  // Connection pool settings
  config.maxRetriesPerRequest = parseInt(process.env['REDIS_MAX_RETRIES'] || '3');
  config.retryDelayOnFailover = parseInt(process.env['REDIS_RETRY_DELAY'] || '1000');
  config.connectTimeout = parseInt(process.env['REDIS_CONNECTION_TIMEOUT'] || '10000');
  config.commandTimeout = parseInt(process.env['REDIS_COMMAND_TIMEOUT'] || '5000');
  config.lazyConnect = true;

  return config;
}

/**
 * Create Redis connection instance
 */
export function createRedisConnection(): Redis {
  if (redis) {
    return redis;
  }

  const config = getRedisConfig();

  redis = new Redis(config as RedisOptions);

  // Connection event handlers
  redis.on('connect', () => {
    console.log('Redis: Connected');
    isConnected = true;
  });

  redis.on('ready', () => {
    console.log('Redis: Ready to accept commands');
  });

  redis.on('error', (error) => {
    console.error('Redis: Connection error:', error);
    isConnected = false;
  });

  redis.on('close', () => {
    console.log('Redis: Connection closed');
    isConnected = false;
  });

  redis.on('reconnecting', () => {
    console.log('Redis: Reconnecting...');
  });

  redis.on('end', () => {
    console.log('Redis: Connection ended');
    isConnected = false;
  });

  return redis;
}

/**
 * Get Redis connection instance
 */
export function getRedis(): Redis {
  if (!redis) {
    return createRedisConnection();
  }
  return redis;
}

/**
 * Test Redis connection
 */
export async function testConnection(): Promise<boolean> {
  try {
    const client = getRedis();
    // Connect if not already connected (lazyConnect: true)
    if (client.status === 'wait') {
      await client.connect();
    }
    await client.ping();
    return true;
  } catch (error) {
    console.error('Redis connection test failed:', error);
    return false;
  }
}

/**
 * Check if Redis is connected
 */
export function isRedisConnected(): boolean {
  return isConnected && redis?.status === 'ready';
}

/**
 * Close Redis connection
 */
export async function closeRedis(): Promise<void> {
  if (redis) {
    await redis.quit();
    redis = null;
    isConnected = false;
  }
}

/**
 * Graceful shutdown handler
 */
export async function gracefulShutdown(): Promise<void> {
  console.log('Redis: Starting graceful shutdown...');
  await closeRedis();
  console.log('Redis: Graceful shutdown completed');
}
