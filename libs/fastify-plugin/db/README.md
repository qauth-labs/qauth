# Fastify Database Plugin

Fastify plugin for PostgreSQL database connection management in QAuth. This plugin wraps the `@qauth/db` library and provides database connection lifecycle management within Fastify applications.

## Overview

The `@qauth/fastify-plugin-db` plugin integrates PostgreSQL into your Fastify application by:

- Decorating the Fastify instance with `db` (Drizzle ORM) and `dbPool` (PostgreSQL connection pool) properties
- Managing database connection lifecycle (connection, verification, graceful shutdown)
- Providing automatic connection testing on server ready
- Handling graceful shutdown on server close

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { databasePlugin } from '@qauth/fastify-plugin-db';
```

## Usage

### Basic Registration

```typescript
import Fastify from 'fastify';
import { databasePlugin } from '@qauth/fastify-plugin-db';

const fastify = Fastify();

// Register the database plugin
await fastify.register(databasePlugin);

// Start the server
await fastify.listen({ port: 3000 });
```

### With Other Plugins

```typescript
import Fastify from 'fastify';
import { databasePlugin } from '@qauth/fastify-plugin-db';
import { cachePlugin } from '@qauth/fastify-plugin-cache';

const fastify = Fastify();

// Register plugins in order
await fastify.register(databasePlugin);
await fastify.register(cachePlugin);

await fastify.listen({ port: 3000 });
```

### Using Database in Routes

Once registered, both Drizzle ORM and the connection pool are available on the Fastify instance:

```typescript
// Using Drizzle ORM
import { schema } from '@qauth/db';
const { users, realms, oauthClients } = schema;

fastify.get('/users', async (request, reply) => {
  // Access Drizzle ORM via fastify.db
  const allUsers = await fastify.db.select().from(users);
  return { users: allUsers };
});

// Using connection pool directly
fastify.get('/health', async (request, reply) => {
  const client = await fastify.dbPool.connect();
  try {
    const result = await client.query('SELECT NOW()');
    return { timestamp: result.rows[0].now };
  } finally {
    client.release();
  }
});
```

### Using Repositories

For type-safe database operations with proper error handling, use the repository pattern:

```typescript
import { usersRepository, realmsRepository } from '@qauth/db';
import { NotFoundError, UniqueConstraintError } from '@qauth/errors';

// Get user by ID
fastify.get('/users/:id', async (request, reply) => {
  const { id } = request.params as { id: string };

  try {
    const user = await usersRepository.findByIdOrThrow(id);
    return { user };
  } catch (error) {
    if (error instanceof NotFoundError) {
      // Use the statusCode property from the error class
      reply.code(error.statusCode).send({ error: error.message });
      return;
    }
    throw error;
  }
});

// Create user
fastify.post('/users', async (request, reply) => {
  const userData = request.body as NewUser;

  try {
    const user = await usersRepository.create(userData);
    reply.code(201).send({ user });
  } catch (error) {
    if (error instanceof UniqueConstraintError) {
      // Use the statusCode property from the error class (409 Conflict)
      reply.code(error.statusCode).send({
        error: 'User already exists',
        constraint: error.constraint,
      });
      return;
    }
    throw error;
  }
});

// Update user
fastify.put('/users/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const updateData = request.body as UpdateUser;

  try {
    const user = await usersRepository.update(id, updateData);
    return { user };
  } catch (error) {
    if (error instanceof NotFoundError) {
      // Use the statusCode property from the error class
      reply.code(error.statusCode).send({ error: error.message });
      return;
    }
    throw error;
  }
});
```

### Using Repositories with Transactions

Repositories support transactions for atomic operations:

```typescript
import { db } from '@qauth/db';
import { usersRepository, realmsRepository } from '@qauth/db';

fastify.post('/setup', async (request, reply) => {
  const { realmName, adminEmail } = request.body;

  // All operations in a single transaction
  const result = await db.transaction(async (tx) => {
    // Create realm
    const realm = await realmsRepository.create({ name: realmName, displayName: realmName }, tx);

    // Create admin user in the same transaction
    const admin = await usersRepository.create(
      {
        realmId: realm.id,
        email: adminEmail,
        passwordHash: await hashPassword('admin123'),
        emailVerified: true,
      },
      tx
    );

    return { realm, admin };
  });

  return result;
});
```

## API

### Plugin Registration

```typescript
await fastify.register(databasePlugin, options?);
```

**Options**: Currently accepts standard Fastify plugin options. No custom options are required. The plugin uses the connection configuration from `@qauth/db`, which reads from environment variables (e.g., `DATABASE_URL`).

### Fastify Instance Decorators

The plugin decorates the Fastify instance with two properties:

#### `fastify.db`

Type: `typeof db` (Drizzle ORM instance)

The Drizzle ORM instance. This is the same instance exported from `@qauth/db`.

**Example**:

```typescript
// Using Drizzle ORM
import { schema } from '@qauth/db';
const { users, realms, oauthClients } = schema;

fastify.get('/users', async (request, reply) => {
  const allUsers = await fastify.db.select().from(users);
  return { users: allUsers };
});

// Query with relations
fastify.get('/users/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const user = await fastify.db.query.users.findFirst({
    where: (users, { eq }) => eq(users.id, id),
    with: {
      realm: true,
    },
  });
  return { user };
});
```

#### `fastify.dbPool`

Type: `Pool` (from `pg`)

The PostgreSQL connection pool. This is the same pool instance exported from `@qauth/db`.

**Example**:

```typescript
// Using connection pool directly
fastify.get('/query', async (request, reply) => {
  const client = await fastify.dbPool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE id = $1', [userId]);
    return { user: result.rows[0] };
  } finally {
    client.release();
  }
});

// Or using pool.query (auto-releases connection)
fastify.get('/simple-query', async (request, reply) => {
  const result = await fastify.dbPool.query('SELECT NOW()');
  return { timestamp: result.rows[0].now };
});
```

## TypeScript Support

The plugin includes TypeScript type definitions. Both `fastify.db` and `fastify.dbPool` are automatically typed:

```typescript
import { FastifyInstance } from 'fastify';

async function myRoute(fastify: FastifyInstance) {
  // TypeScript knows about fastify.db and fastify.dbPool
  const result = await fastify.dbPool.query('SELECT * FROM users');
  const users = result.rows;
}
```

## Configuration

The plugin uses the same environment variables as `@qauth/db`. Configure database connection in your `.env` file:

```bash
# Database URL (recommended)
DATABASE_URL=postgresql://username:password@host:port/database

# Connection Pool Settings
DB_POOL_MAX=20
DB_POOL_MIN=2
DB_POOL_IDLE_TIMEOUT=10000
DB_POOL_CONNECTION_TIMEOUT=2000
```

For detailed configuration options, see the [`@qauth/db` README](../data-access/db/README.md).

## Lifecycle Hooks

The plugin automatically manages database connection lifecycle:

### `onReady` Hook

When the Fastify server becomes ready, the plugin:

1. Tests the database connection
2. Logs a warning if the connection test fails
3. Logs an info message if the connection is verified

```typescript
// This happens automatically
fastify.addHook('onReady', async () => {
  const isConnected = await testConnection();
  if (!isConnected) {
    fastify.log.warn('Database connection test failed on ready');
  } else {
    fastify.log.info('Database connection verified');
  }
});
```

### `onClose` Hook

When the Fastify server is closing, the plugin:

1. Logs that it's closing the database connection
2. Calls `pool.end()` to gracefully close all connections
3. Logs confirmation that the connection is closed

```typescript
// This happens automatically
fastify.addHook('onClose', async () => {
  fastify.log.info('Closing database connection...');
  await pool.end();
  fastify.log.info('Database connection closed');
});
```

## Integration with @qauth/db

This plugin wraps the `@qauth/db` library. The underlying database connection is managed by `@qauth/db`, and this plugin provides Fastify-specific lifecycle management.

You can still use utilities from `@qauth/db` directly:

```typescript
import { db, pool, testConnection } from '@qauth/db';

// These use the same database connection
const isConnected = await testConnection();
const result = await pool.query('SELECT NOW()');
```

## Error Handling

The plugin handles errors gracefully:

- **Connection failures**: Logged as warnings, but don't prevent server startup
- **Shutdown errors**: Logged but don't prevent graceful shutdown
- **Database operations**: Should be wrapped in try-catch blocks in your route handlers

```typescript
fastify.get('/safe-query', async (request, reply) => {
  try {
    const result = await fastify.dbPool.query('SELECT * FROM users');
    return { users: result.rows };
  } catch (error) {
    fastify.log.error(error, 'Database operation failed');
    reply.code(500).send({ error: 'Database unavailable' });
  }
});
```

## Best Practices

1. **Register Early**: Register the database plugin early in your plugin registration order, especially if other plugins depend on the database.

2. **Connection Pooling**: Always use the connection pool (`fastify.dbPool`) rather than creating new connections. The pool manages connections efficiently.

3. **Release Connections**: When using `pool.connect()`, always release the connection in a `finally` block to prevent connection leaks.

4. **Error Handling**: Always wrap database operations in try-catch blocks in production code.

5. **Connection Testing**: The plugin automatically tests connections on ready, but you can also test manually using utilities from `@qauth/db`.

6. **Graceful Shutdown**: The plugin handles graceful shutdown automatically. Ensure your Fastify server properly handles SIGTERM and SIGINT signals.

7. **Use Drizzle ORM**: For type-safe database operations, prefer using Drizzle ORM (`fastify.db`) over raw SQL queries when possible.

## Example: Complete Integration

```typescript
import Fastify from 'fastify';
import { databasePlugin } from '@qauth/fastify-plugin-db';

const fastify = Fastify();

// Register database plugin
await fastify.register(databasePlugin);

// Health check using connection pool
fastify.get('/health', async (request, reply) => {
  try {
    const result = await fastify.dbPool.query('SELECT NOW()');
    return {
      status: 'healthy',
      timestamp: result.rows[0].now,
    };
  } catch (error) {
    fastify.log.error(error, 'Health check failed');
    reply.code(503).send({ status: 'unhealthy' });
  }
});

// Example route with proper connection management
fastify.get('/users/:id', async (request, reply) => {
  const { id } = request.params as { id: string };

  const client = await fastify.dbPool.connect();
  try {
    const result = await client.query('SELECT * FROM users WHERE id = $1', [id]);

    if (result.rows.length === 0) {
      reply.code(404).send({ error: 'User not found' });
      return;
    }

    return { user: result.rows[0] };
  } catch (error) {
    fastify.log.error(error, 'Failed to fetch user');
    reply.code(500).send({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});

await fastify.listen({ port: 3000 });
```

## Migrations

Database migrations are managed through the `@qauth/db` library. See the [`@qauth/db` README](../data-access/db/README.md) for migration commands.

## Development

### Running Tests

```bash
nx test fastify-plugin-db
```

### Linting

```bash
nx lint fastify-plugin-db
```

## Dependencies

- `@qauth/db`: Core database connection and Drizzle ORM
- `fastify-plugin`: Fastify plugin wrapper
- `pg`: PostgreSQL client (via `@qauth/db`)
- `drizzle-orm`: TypeScript ORM (via `@qauth/db`)

## Related Libraries

- [`@qauth/db`](../data-access/db/README.md): Core database utilities, Drizzle ORM, and repository pattern
- [`@qauth/errors`](../common/errors/README.md): Error classes used by repositories
- [`@qauth/fastify-plugin-cache`](../fastify-plugin/cache/README.md): Cache plugin for Fastify

## License

Apache-2.0
