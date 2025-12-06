# QAuth Database Module

This library provides database connectivity and management for the QAuth platform using PostgreSQL and Drizzle ORM.

## Overview

This is the foundational database module for Phase 0 (P0) - configuration only, no actual table schemas. The actual database schemas will be implemented in Phase 1 (P1).

## Features

- PostgreSQL connection management with connection pooling
- Drizzle ORM integration
- Migration system ready for use
- Database connection utilities and testing functions
- Nx integration for consistent tooling

## Setup

### 1. Environment Configuration

Copy `.env.example` to `.env` and configure your database connection:

```bash
cp .env.example .env
```

Update the following variables in your `.env` file:

```env
DATABASE_URL=postgresql://username:password@host:port/database
DB_POOL_MAX=20
DB_POOL_MIN=2
DB_POOL_IDLE_TIMEOUT=10000
DB_POOL_CONNECTION_TIMEOUT=2000
```

### 2. Database Setup

Ensure you have PostgreSQL running and create a database:

```sql
CREATE DATABASE qauth_dev;
```

## Usage

### Basic Database Connection

```typescript
import { db, pool, testConnection } from '@qauth/data-access/db';

// Test database connection
const isConnected = await testConnection();
console.log('Database connected:', isConnected);

// Use Drizzle ORM
// Note: Actual schemas will be available in P1
```

### Connection Pool Management

```typescript
import { pool, closeDatabase } from '@qauth/data-access/db';

// Direct pool access if needed
const client = await pool.connect();
try {
  const result = await client.query('SELECT NOW()');
  console.log(result.rows[0]);
} finally {
  client.release();
}

// Graceful shutdown
await closeDatabase();
```

## Available Nx Commands

This library provides several Nx targets for database management:

### Migration Commands

```bash
# Generate new migration files
nx run db:db:generate

# Run pending migrations
nx run db:db:migrate

# Push schema changes directly (dev only)
nx run db:db:push
```

### Database Management

```bash
# Open Drizzle Studio for database management
nx run db:db:studio

# Drop all tables (DANGER: use with caution)
nx run db:db:drop
```

## Project Structure

```
libs/data-access/db/
├── src/
│   ├── lib/
│   │   ├── db.ts              # Database connection and utilities
│   │   └── schema/
│   │       └── index.ts       # Database schemas (empty in P0)
│   └── index.ts               # Public API exports
├── drizzle.config.ts          # Drizzle configuration
├── project.json               # Nx project configuration
└── README.md                  # This file
```

## Development

### Adding New Schemas (P1)

When implementing actual database schemas in P1:

1. Create schema files in `src/lib/schema/`
2. Export them from `src/lib/schema/index.ts`
3. Generate migrations using `nx run db:db:generate`
4. Run migrations using `nx run db:db:migrate`

### Testing Database Connection

```typescript
import { testConnection } from '@qauth/data-access/db';

// Test in your application startup
const isConnected = await testConnection();
if (!isConnected) {
  throw new Error('Failed to connect to database');
}
```

## Fastify Integration

For Fastify applications, use the [`@qauth/fastify-plugin-db`](../../fastify-plugin/db/README.md) plugin which wraps this library and provides:

- Automatic database connection lifecycle management
- Fastify instance decoration with `fastify.db` (Drizzle ORM) and `fastify.dbPool` (connection pool)
- Integration with Fastify's `onReady` and `onClose` hooks
- TypeScript type definitions for Fastify

**Example with Fastify**:

```typescript
import Fastify from 'fastify';
import { databasePlugin } from '@qauth/fastify-plugin-db';

const fastify = Fastify();

// Register the database plugin
await fastify.register(databasePlugin);

// Use Drizzle ORM via fastify.db (when schemas are available in P1)
fastify.get('/users', async (request, reply) => {
  // const users = await fastify.db.select().from(usersTable);
  return { users: [] };
});

// Or use connection pool directly
fastify.get('/health', async (request, reply) => {
  const result = await fastify.dbPool.query('SELECT NOW()');
  return { timestamp: result.rows[0].now };
});
```

The Fastify plugin automatically manages the database connection lifecycle, so you don't need to manually call `closeDatabase()` when using the plugin.

## What's Next (P1)

The following features will be implemented in Phase 1:

- User authentication tables (users, sessions, etc.)
- OAuth 2.1 client management tables
- Post-quantum cryptography key storage
- Audit logging tables
- Complete CRUD operations
- Database seeding and fixtures

## Related Libraries

- [`@qauth/fastify-plugin-db`](../../fastify-plugin/db/README.md): Fastify plugin wrapper for this library

## Dependencies

- `drizzle-orm`: TypeScript ORM for PostgreSQL
- `pg`: PostgreSQL client for Node.js
- `drizzle-kit`: Database toolkit and migration generator
- `dotenv`: Environment variable management

## License

Apache-2.0
