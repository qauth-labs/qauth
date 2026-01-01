import type Redis from 'ioredis';

/**
 * Cache client type - abstracted from implementation
 * Currently uses ioredis Redis, but can be replaced with other cache implementations
 */
export type CacheClient = Redis;

/**
 * Redis connection configuration interface
 */
export interface RedisConfig {
  /** Redis connection URL (takes precedence over individual settings) */
  url?: string;
  /** Redis host address (used if url is not set) */
  host?: string;
  /** Redis port number (used if url is not set) @default 6379 */
  port?: number;
  /** Redis password */
  password?: string;
  /** Redis database number @default 0 */
  db?: number;
  /** Maximum retries per request @default 3 */
  maxRetriesPerRequest?: number;
  /** Connection timeout in milliseconds @default 10000 */
  connectTimeout?: number;
  /** Command timeout in milliseconds @default 5000 */
  commandTimeout?: number;
  /** Whether to use lazy connection (connect on first command) @default true */
  lazyConnect?: boolean;
}
