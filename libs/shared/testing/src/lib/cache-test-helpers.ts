import { RedisContainer, StartedRedisContainer } from '@testcontainers/redis';
import Redis from 'ioredis';

let container: StartedRedisContainer | null = null;
let client: Redis | null = null;

/**
 * Start a Redis test container
 * @returns Started container and Redis client
 */
export async function startTestRedis(): Promise<{
  container: StartedRedisContainer;
  client: Redis;
  host: string;
  port: number;
}> {
  if (container && client) {
    return {
      container,
      client,
      host: container.getHost(),
      port: container.getPort(),
    };
  }

  container = await new RedisContainer('redis:7.4-alpine').start();
  const host = container.getHost();
  const port = container.getPort();

  client = new Redis({
    host,
    port,
  });

  return { container, client, host, port };
}

/**
 * Stop the Redis test container
 */
export async function stopTestRedis(): Promise<void> {
  if (client) {
    await client.quit();
    client = null;
  }
  if (container) {
    await container.stop();
    container = null;
  }
}

/**
 * Get the current test Redis client
 * @returns Redis client or null if not started
 */
export function getTestRedisClient(): Redis | null {
  return client;
}

/**
 * Clear all keys from the test Redis instance
 */
export async function clearTestRedis(): Promise<void> {
  if (client) {
    await client.flushall();
  }
}
