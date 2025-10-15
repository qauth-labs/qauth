// Redis client configuration and connection management
// Production-ready Redis client with automatic reconnection and error handling

import {
  REDIS_COMMAND_TIMEOUT,
  REDIS_CONNECTION_TIMEOUT,
  REDIS_RETRY_CONFIG,
} from '@qauth/constants';
import Redis, { RedisOptions } from 'ioredis';

// =============================================================================
// Redis Configuration
// =============================================================================

export interface RedisConfig {
  url?: string;
  host?: string;
  port?: number;
  password?: string;
  db?: number;
  retryStrategy?: (times: number) => number | null;
  maxRetriesPerRequest?: number;
  lazyConnect?: boolean;
  connectTimeout?: number;
  commandTimeout?: number;
}

// =============================================================================
// Redis Client Class
// =============================================================================

export class RedisClient {
  private redis: Redis;
  private isConnected = false;

  constructor(config: RedisConfig) {
    const options: RedisOptions = {
      // Connection settings
      host: config.host || 'localhost',
      port: config.port || 6379,
      password: config.password,
      db: config.db || 0,

      // Timeout settings
      connectTimeout: config.connectTimeout || REDIS_CONNECTION_TIMEOUT,
      commandTimeout: config.commandTimeout || REDIS_COMMAND_TIMEOUT,

      // Retry strategy with exponential backoff
      retryStrategy: config.retryStrategy || this.createRetryStrategy(),
      maxRetriesPerRequest: config.maxRetriesPerRequest || REDIS_RETRY_CONFIG.retries,

      // Connection behavior
      lazyConnect: config.lazyConnect !== false, // Default to true

      // Production settings
      keepAlive: 30000,
      family: 4, // IPv4
      keyPrefix: 'qauth:', // Namespace all keys
    };

    // Use URL if provided (overrides individual settings)
    if (config.url) {
      this.redis = new Redis(config.url, options);
    } else {
      this.redis = new Redis(options);
    }

    this.setupEventHandlers();
  }

  // =============================================================================
  // Event Handlers
  // =============================================================================

  private setupEventHandlers(): void {
    this.redis.on('connect', () => {
      console.log('Redis client connected');
      this.isConnected = true;
    });

    this.redis.on('ready', () => {
      console.log('Redis client ready');
      this.isConnected = true;
    });

    this.redis.on('error', (error) => {
      console.error('Redis client error:', error);
      this.isConnected = false;
    });

    this.redis.on('close', () => {
      console.log('Redis client connection closed');
      this.isConnected = false;
    });

    this.redis.on('reconnecting', () => {
      console.log('Redis client reconnecting...');
    });

    this.redis.on('end', () => {
      console.log('Redis client connection ended');
      this.isConnected = false;
    });
  }

  // =============================================================================
  // Retry Strategy
  // =============================================================================

  private createRetryStrategy() {
    return (times: number): number | null => {
      if (times > REDIS_RETRY_CONFIG.retries) {
        console.error(`Redis connection failed after ${times} attempts`);
        return null; // Stop retrying
      }

      // Exponential backoff with jitter
      const delay = Math.min(
        REDIS_RETRY_CONFIG.maxDelay,
        Math.pow(2, times) * 100 + Math.random() * 100
      );

      console.log(`Redis retry attempt ${times} in ${delay}ms`);
      return delay;
    };
  }

  // =============================================================================
  // Connection Management
  // =============================================================================

  /**
   * Connect to Redis (if lazyConnect is enabled)
   */
  async connect(): Promise<void> {
    if (!this.isConnected) {
      await this.redis.connect();
    }
  }

  /**
   * Disconnect from Redis
   */
  async disconnect(): Promise<void> {
    await this.redis.quit();
    this.isConnected = false;
  }

  /**
   * Check if Redis is connected and responding
   */
  async ping(): Promise<boolean> {
    try {
      const result = await this.redis.ping();
      return result === 'PONG';
    } catch (error) {
      console.error('Redis ping failed:', error);
      return false;
    }
  }

  /**
   * Get connection status
   */
  get connected(): boolean {
    return this.isConnected && this.redis.status === 'ready';
  }

  /**
   * Get Redis instance for direct access
   */
  get client(): Redis {
    return this.redis;
  }

  // =============================================================================
  // Session Management Methods
  // =============================================================================

  /**
   * Set session data with TTL
   * Uses SETEX for atomic set+expire operation
   */
  async setSession(sessionId: string, data: any, ttlSeconds: number): Promise<void> {
    const key = `session:${sessionId}`;
    const value = JSON.stringify(data);

    try {
      await this.redis.setex(key, ttlSeconds, value);
    } catch (error) {
      console.error(`Failed to set session ${sessionId}:`, error);
      throw error;
    }
  }

  /**
   * Get session data
   */
  async getSession(sessionId: string): Promise<any | null> {
    const key = `session:${sessionId}`;

    try {
      const value = await this.redis.get(key);
      if (!value) return null;

      return JSON.parse(value);
    } catch (error) {
      console.error(`Failed to get session ${sessionId}:`, error);
      return null;
    }
  }

  /**
   * Delete session
   */
  async deleteSession(sessionId: string): Promise<boolean> {
    const key = `session:${sessionId}`;

    try {
      const result = await this.redis.del(key);
      return result > 0;
    } catch (error) {
      console.error(`Failed to delete session ${sessionId}:`, error);
      return false;
    }
  }

  /**
   * Update session TTL
   */
  async updateSessionTTL(sessionId: string, ttlSeconds: number): Promise<boolean> {
    const key = `session:${sessionId}`;

    try {
      const result = await this.redis.expire(key, ttlSeconds);
      return result === 1;
    } catch (error) {
      console.error(`Failed to update TTL for session ${sessionId}:`, error);
      return false;
    }
  }

  /**
   * Delete all sessions for a user
   * Uses SCAN to avoid blocking Redis (never use KEYS in production)
   */
  async deleteUserSessions(userId: string): Promise<number> {
    const pattern = `session:*`;
    let cursor = '0';
    let deletedCount = 0;

    try {
      do {
        const result = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 100);
        cursor = result[0];
        const keys = result[1];

        // Filter keys that belong to this user
        const userSessionKeys = [];
        for (const key of keys) {
          const sessionData = await this.redis.get(key);
          if (sessionData) {
            try {
              const parsed = JSON.parse(sessionData);
              if (parsed.userId === userId) {
                userSessionKeys.push(key);
              }
            } catch (parseError) {
              // Skip invalid session data
              console.warn(`Invalid session data in key ${key}`);
            }
          }
        }

        // Delete user's sessions
        if (userSessionKeys.length > 0) {
          const deleted = await this.redis.del(...userSessionKeys);
          deletedCount += deleted;
        }
      } while (cursor !== '0');

      return deletedCount;
    } catch (error) {
      console.error(`Failed to delete sessions for user ${userId}:`, error);
      return 0;
    }
  }

  /**
   * Clean up expired sessions (should be called periodically)
   * Redis automatically expires keys, but this provides statistics
   */
  async getSessionStats(): Promise<{
    totalSessions: number;
    memoryUsage: string;
  }> {
    try {
      const pattern = `session:*`;
      let cursor = '0';
      let totalSessions = 0;

      // Count sessions
      do {
        const result = await this.redis.scan(cursor, 'MATCH', pattern, 'COUNT', 1000);
        cursor = result[0];
        totalSessions += result[1].length;
      } while (cursor !== '0');

      // Get memory usage
      const info = await this.redis.info('memory');
      const memoryMatch = info.match(/used_memory_human:(.+)/);
      const memoryUsage = memoryMatch ? memoryMatch[1].trim() : 'unknown';

      return {
        totalSessions,
        memoryUsage,
      };
    } catch (error) {
      console.error('Failed to get session stats:', error);
      return {
        totalSessions: 0,
        memoryUsage: 'unknown',
      };
    }
  }

  // =============================================================================
  // Utility Methods
  // =============================================================================

  /**
   * Flush all keys (for testing only)
   */
  async flushAll(): Promise<void> {
    await this.redis.flushdb();
  }

  /**
   * Get Redis info
   */
  async getInfo(section?: string): Promise<string> {
    if (section) {
      return this.redis.info(section);
    } else {
      return this.redis.info();
    }
  }
}

// =============================================================================
// Global Redis Instance
// =============================================================================

let redisClient: RedisClient | null = null;

/**
 * Initialize the global Redis client
 */
export function initializeRedis(config: RedisConfig): RedisClient {
  if (redisClient) {
    throw new Error('Redis client already initialized');
  }

  redisClient = new RedisClient(config);
  return redisClient;
}

/**
 * Get the global Redis client
 */
export function getRedis(): RedisClient {
  if (!redisClient) {
    throw new Error('Redis client not initialized. Call initializeRedis() first.');
  }

  return redisClient;
}

/**
 * Close the global Redis client
 */
export async function closeRedis(): Promise<void> {
  if (redisClient) {
    await redisClient.disconnect();
    redisClient = null;
  }
}
