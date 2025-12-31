# QAuth Cache Library

Redis connection and caching utilities for the QAuth project.

> **Note**: This is the core cache library. For Fastify integration, use [`@qauth/fastify-plugin-cache`](../../fastify/plugins/cache/README.md) which wraps this library and provides Fastify-specific lifecycle management.

## Overview

This library provides a comprehensive Redis integration for QAuth, including:

- **Redis Connection Management**: Robust connection handling with retry logic and error recovery
- **Session Storage**: Utilities for managing user sessions with TTL support
- **Rate Limiting**: Built-in rate limiting utilities for API protection
- **Caching**: General-purpose caching utilities with JSON serialization
- **User Data**: User-specific data storage and retrieval
- **Token Management**: Token blacklisting and validation utilities

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

## Environment Configuration

Add the following environment variables to your `.env` file:

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
```

## Usage

### Basic Connection

```typescript
import { getRedis, testConnection, isRedisConnected } from '@qauth/infra-cache';

// Test connection
const isConnected = await testConnection();
console.log('Redis connected:', isConnected);

// Check connection status
if (isRedisConnected()) {
  console.log('Redis is ready');
}
```

### Session Management

```typescript
import { SessionUtils } from '@qauth/infra-cache';

// Set session data
await SessionUtils.setSession(
  'user123',
  {
    userId: 'user123',
    email: 'user@example.com',
    role: 'admin',
  },
  3600
); // 1 hour TTL

// Get session data
const session = await SessionUtils.getSession('user123');
console.log(session); // { userId: 'user123', email: 'user@example.com', role: 'admin' }

// Check if session exists
const exists = await SessionUtils.hasSession('user123');

// Extend session TTL
await SessionUtils.extendSession('user123', 7200); // 2 hours

// Delete session
await SessionUtils.deleteSession('user123');
```

### Rate Limiting

```typescript
import { RateLimitUtils } from '@qauth/infra-cache';

// Check rate limit
const result = await RateLimitUtils.checkRateLimit('user123', 10, 60); // 10 requests per minute
if (!result.allowed) {
  throw new Error('Rate limit exceeded');
}

// Get rate limit status
const status = await RateLimitUtils.getRateLimitStatus('user123', 10);
console.log(`Remaining: ${status.remaining}, Reset: ${new Date(status.resetTime)}`);

// Reset rate limit
await RateLimitUtils.resetRateLimit('user123');
```

### Caching

```typescript
import { CacheUtils } from '@qauth/infra-cache';

// Set cache
await CacheUtils.setCache(
  'user:profile:123',
  {
    name: 'John Doe',
    email: 'john@example.com',
  },
  300
); // 5 minutes TTL

// Get cache
const profile = await CacheUtils.getCache('user:profile:123');

// Get or set cache with fallback
const data = await CacheUtils.getOrSetCache(
  'expensive:data:123',
  async () => {
    // Expensive operation
    return await fetchExpensiveData();
  },
  600 // 10 minutes TTL
);

// Check if cache exists
const exists = await CacheUtils.hasCache('user:profile:123');

// Delete cache
await CacheUtils.deleteCache('user:profile:123');
```

### User Data

```typescript
import { UserUtils } from '@qauth/infra-cache';

// Set user data
await UserUtils.setUserData(
  'user123',
  {
    preferences: { theme: 'dark' },
    lastLogin: new Date().toISOString(),
  },
  1800
); // 30 minutes TTL

// Get user data
const userData = await UserUtils.getUserData('user123');

// Delete user data
await UserUtils.deleteUserData('user123');
```

### Token Management

```typescript
import { TokenUtils } from '@qauth/infra-cache';

// Blacklist token
await TokenUtils.blacklistToken('jwt-token-here', 900); // 15 minutes TTL

// Check if token is blacklisted
const isBlacklisted = await TokenUtils.isTokenBlacklisted('jwt-token-here');

// Remove from blacklist
await TokenUtils.unblacklistToken('jwt-token-here');
```

## Key Prefixes

The library uses consistent key prefixes for different data types:

- `session:` - User sessions
- `rate:` - Rate limiting counters
- `cache:` - General cache data
- `user:` - User-specific data
- `token:` - Token blacklist

## Default TTL Values

- **Session**: 24 hours
- **Rate Limit**: 1 minute
- **Cache**: 5 minutes
- **User**: 30 minutes
- **Token**: 15 minutes

## Error Handling

The library includes comprehensive error handling:

- Connection retry logic with exponential backoff
- Graceful degradation when Redis is unavailable
- Automatic reconnection on connection loss
- Proper cleanup on application shutdown

## Graceful Shutdown

The library automatically handles graceful shutdown:

```typescript
import { gracefulShutdown } from '@qauth/infra-cache';

// Manual graceful shutdown
await gracefulShutdown();
```

## Fastify Integration

For Fastify applications, use the [`@qauth/fastify-plugin-cache`](../../fastify/plugins/cache/README.md) plugin which wraps this library and provides:

- Automatic Redis connection lifecycle management
- Fastify instance decoration with `fastify.redis`
- Integration with Fastify's `onReady` and `onClose` hooks
- TypeScript type definitions for Fastify

**Example with Fastify**:

```typescript
import Fastify from 'fastify';
import { cachePlugin } from '@qauth/fastify-plugin-cache';
import { SessionUtils } from '@qauth/infra-cache';

const fastify = Fastify();

// Register the cache plugin
await fastify.register(cachePlugin);

// Use Redis directly via fastify.redis
fastify.get('/cache', async (request, reply) => {
  const value = await fastify.redis.get('key');
  return { value };
});

// Or use utility functions (they use the same Redis connection)
fastify.post('/session', async (request, reply) => {
  const { userId, data } = request.body;
  await SessionUtils.setSession(userId, data, 3600);
  return { success: true };
});
```

The Fastify plugin automatically manages the Redis connection lifecycle, so you don't need to manually call `gracefulShutdown()` when using the plugin.

## Best Practices

1. **Key Naming**: Use descriptive, hierarchical keys
2. **TTL Management**: Set appropriate TTL values based on data sensitivity
3. **Error Handling**: Always handle potential Redis connection errors
4. **Connection Testing**: Test Redis connection before critical operations
5. **Resource Cleanup**: Use graceful shutdown in production

## Development

### Running Tests

```bash
nx test cache
```

### Linting

```bash
nx lint cache
```

## Architecture Notes

This library provides the foundation for:

- **Session Management**: Full session lifecycle management with TTL support
- **Rate Limiting**: API rate limiting utilities for protection
- **Token Management**: JWT token blacklisting and validation
- **Caching**: User data and application state caching with JSON serialization

The utility classes provide a complete set of operations for these features while maintaining a clean, type-safe API.

## Related Libraries

- [`@qauth/fastify-plugin-cache`](../../fastify/plugins/cache/README.md): Fastify plugin wrapper for this library

## Dependencies

- `ioredis`: Redis client for Node.js with TypeScript support
- Built-in connection pooling and clustering support
- Promise-based API for async/await patterns
