# Fastify Cache Plugin

Fastify plugin for Redis connection management in QAuth. This plugin wraps the `@qauth/cache` library and provides Redis connection lifecycle management within Fastify applications.

## Overview

The `@qauth/fastify-plugin-cache` plugin integrates Redis into your Fastify application by:

- Decorating the Fastify instance with a `redis` property
- Managing Redis connection lifecycle (connection, verification, graceful shutdown)
- Providing automatic connection testing on server ready
- Handling graceful shutdown on server close

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { cachePlugin } from '@qauth/fastify-plugin-cache';
```

## Usage

### Basic Registration

```typescript
import Fastify from 'fastify';
import { cachePlugin } from '@qauth/fastify-plugin-cache';

const fastify = Fastify();

// Register the cache plugin
await fastify.register(cachePlugin);

// Start the server
await fastify.listen({ port: 3000 });
```

### With Other Plugins

```typescript
import Fastify from 'fastify';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { databasePlugin } from '@qauth/fastify-plugin-db';

const fastify = Fastify();

// Register plugins in order
await fastify.register(databasePlugin);
await fastify.register(cachePlugin);

await fastify.listen({ port: 3000 });
```

### Using Redis in Routes

Once registered, the Redis client is available on the Fastify instance:

```typescript
fastify.get('/cache-example', async (request, reply) => {
  // Access Redis client via fastify.redis
  const value = await fastify.redis.get('my-key');
  return { value };
});

fastify.post('/cache-example', async (request, reply) => {
  const { key, value } = request.body as { key: string; value: string };
  await fastify.redis.set(key, value);
  return { success: true };
});
```

## API

### Plugin Registration

```typescript
await fastify.register(cachePlugin, options?);
```

**Options**: Currently accepts standard Fastify plugin options. No custom options are required.

### Fastify Instance Decorator

The plugin decorates the Fastify instance with:

#### `fastify.redis`

Type: `Redis` (from `ioredis`)

The Redis client instance. This is the same instance returned by `getRedis()` from `@qauth/cache`.

**Example**:

```typescript
// Get a value
const value = await fastify.redis.get('key');

// Set a value
await fastify.redis.set('key', 'value');

// Set with TTL
await fastify.redis.setex('key', 3600, 'value');

// Delete a key
await fastify.redis.del('key');

// Check if key exists
const exists = await fastify.redis.exists('key');
```

For more advanced Redis operations, refer to the [ioredis documentation](https://github.com/redis/ioredis).

## TypeScript Support

The plugin includes TypeScript type definitions. The `fastify.redis` property is automatically typed:

```typescript
import { FastifyInstance } from 'fastify';

async function myRoute(fastify: FastifyInstance) {
  // TypeScript knows about fastify.redis
  const value: string | null = await fastify.redis.get('key');
}
```

## Configuration

The plugin uses the same environment variables as `@qauth/cache`. Configure Redis connection in your `.env` file:

```bash
# Redis Configuration
REDIS_URL=redis://localhost:6379/0

# Alternative configuration (if REDIS_URL is not provided)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=your_redis_password
REDIS_DB=0

# Connection Pool Settings
REDIS_MAX_CONNECTIONS=10
REDIS_MIN_CONNECTIONS=2
REDIS_CONNECTION_TIMEOUT=10000
REDIS_COMMAND_TIMEOUT=5000

# Retry Configuration
REDIS_MAX_RETRIES=3
REDIS_RETRY_DELAY=1000
```

For detailed configuration options, see the [`@qauth/cache` README](../../infra/cache/README.md).

## Lifecycle Hooks

The plugin automatically manages Redis connection lifecycle:

### `onReady` Hook

When the Fastify server becomes ready, the plugin:

1. Tests the Redis connection
2. Logs a warning if the connection test fails
3. Logs an info message if the connection is verified

```typescript
// This happens automatically
fastify.addHook('onReady', async () => {
  const isConnected = await testConnection();
  if (!isConnected) {
    fastify.log.warn('Redis connection test failed on ready');
  } else {
    fastify.log.info('Redis connection verified');
  }
});
```

### `onClose` Hook

When the Fastify server is closing, the plugin:

1. Logs that it's closing the Redis connection
2. Calls `redis.quit()` to gracefully close the connection
3. Logs confirmation that the connection is closed

```typescript
// This happens automatically
fastify.addHook('onClose', async () => {
  fastify.log.info('Closing Redis connection...');
  await redis.quit();
  fastify.log.info('Redis connection closed');
});
```

## Integration with @qauth/cache

This plugin wraps the `@qauth/cache` library. The underlying Redis connection is managed by `@qauth/cache`, and this plugin provides Fastify-specific lifecycle management.

You can still use utilities from `@qauth/cache` directly:

```typescript
import { SessionUtils, CacheUtils } from '@qauth/cache';

// These utilities use the same Redis connection
await SessionUtils.setSession('user123', data, 3600);
await CacheUtils.setCache('key', value, 300);
```

## Error Handling

The plugin handles errors gracefully:

- **Connection failures**: Logged as warnings, but don't prevent server startup
- **Shutdown errors**: Logged but don't prevent graceful shutdown
- **Redis operations**: Should be wrapped in try-catch blocks in your route handlers

```typescript
fastify.get('/safe-cache', async (request, reply) => {
  try {
    const value = await fastify.redis.get('key');
    return { value };
  } catch (error) {
    fastify.log.error(error, 'Redis operation failed');
    reply.code(500).send({ error: 'Cache unavailable' });
  }
});
```

## Best Practices

1. **Register Early**: Register the cache plugin early in your plugin registration order, especially if other plugins depend on Redis.

2. **Error Handling**: Always wrap Redis operations in try-catch blocks in production code.

3. **Connection Testing**: The plugin automatically tests connections on ready, but you can also test manually using utilities from `@qauth/cache`.

4. **Graceful Shutdown**: The plugin handles graceful shutdown automatically. Ensure your Fastify server properly handles SIGTERM and SIGINT signals.

5. **Use Utilities**: For common operations (sessions, caching, rate limiting), prefer using utilities from `@qauth/cache` rather than direct Redis commands.

## Example: Complete Integration

```typescript
import Fastify from 'fastify';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { SessionUtils } from '@qauth/cache';

const fastify = Fastify();

// Register cache plugin
await fastify.register(cachePlugin);

// Use Redis in routes
fastify.post('/login', async (request, reply) => {
  const { userId, sessionData } = request.body;

  // Use utility functions
  await SessionUtils.setSession(userId, sessionData, 3600);

  // Or use direct Redis access
  await fastify.redis.set(`user:${userId}:last-login`, new Date().toISOString());

  return { success: true };
});

fastify.get('/session/:userId', async (request, reply) => {
  const { userId } = request.params as { userId: string };
  const session = await SessionUtils.getSession(userId);

  if (!session) {
    reply.code(404).send({ error: 'Session not found' });
    return;
  }

  return { session };
});

await fastify.listen({ port: 3000 });
```

## Development

### Running Tests

```bash
nx test fastify-plugin-cache
```

### Linting

```bash
nx lint fastify-plugin-cache
```

## Dependencies

- `@qauth/cache`: Core Redis connection and utilities
- `fastify-plugin`: Fastify plugin wrapper
- `ioredis`: Redis client (via `@qauth/cache`)

## Related Libraries

- [`@qauth/cache`](../../infra/cache/README.md): Core Redis utilities and connection management
- [`@qauth/fastify-plugin-db`](../db/README.md): Database plugin for Fastify

## License

Apache-2.0
