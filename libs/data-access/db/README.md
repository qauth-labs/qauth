# QAuth Database Module

This library provides database connectivity and management for the QAuth platform using PostgreSQL and Drizzle ORM.

## Overview

This library provides the complete database schema and connection management for QAuth, an OAuth 2.1/OIDC authentication server. It includes all necessary tables for user management, OAuth clients, tokens, sessions, audit logging, and multi-tenancy support.

## Features

- **Complete OAuth 2.1/OIDC Schema**: All tables needed for authentication and authorization
- **Multi-tenancy Support**: Realm-based isolation for multiple tenants
- **PostgreSQL Optimizations**: UUIDv7 primary keys, JSONB for flexible data, optimized indexes
- **Type Safety**: TypeScript enums for grant types, response types, and other constants
- **PostgreSQL connection management** with connection pooling
- **Drizzle ORM integration** with full schema definitions
- **Migration system** ready for use
- **Database connection utilities** and testing functions
- **Nx integration** for consistent tooling

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

**QAuth requires PostgreSQL 18 or later** for native `uuidv7()` support.

Ensure you have PostgreSQL 18+ running and create a database:

```sql
CREATE DATABASE qauth_dev;
```

**Why PostgreSQL 18+?**

- Native `uuidv7()` function (no extension needed)
- Better performance with time-ordered UUIDs
- Modern PostgreSQL features

## Usage

### Basic Database Connection

```typescript
import { db, pool, testConnection, schema } from '@qauth/db';
const { users, oauthClients, realms } = schema;

// Test database connection
const isConnected = await testConnection();
console.log('Database connected:', isConnected);

// Use Drizzle ORM with schemas
import { db, schema } from '@qauth/db';
const { users, realms, oauthClients } = schema;

const allUsers = await db.select().from(users);
const realm = await db.query.realms.findFirst({
  where: (realms, { eq }) => eq(realms.name, 'my-realm'),
});

// Create a new OAuth client
const newClient = await db
  .insert(oauthClients)
  .values({
    realmId: realm.id,
    clientId: 'my-app',
    clientSecretHash: 'argon2id_hash_here',
    name: 'My Application',
    redirectUris: ['https://myapp.com/callback'],
    grantTypes: ['authorization_code', 'refresh_token'],
    responseTypes: ['code'],
  })
  .returning();
```

### Connection Pool Management

```typescript
import { pool, closeDatabase } from '@qauth/db';

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
│   │       ├── index.ts        # Main schema exports
│   │       ├── core.ts         # Core tables: realms, users, oauth_clients
│   │       ├── tokens.ts       # Token tables: email_verification, authorization_codes, refresh_tokens
│   │       ├── sessions.ts     # Session management
│   │       ├── audit.ts        # Audit logging
│   │       ├── roles.ts        # Roles and permissions
│   │       ├── enums.ts        # PostgreSQL enum types
│   │       └── sql-helpers.ts  # SQL helper functions
│   └── index.ts               # Public API exports
├── drizzle.config.ts          # Drizzle configuration
├── project.json               # Nx project configuration
└── README.md                  # This file
```

## Schema Overview

### Core Tables

- **realms**: Multi-tenancy support, each realm is an isolated tenant
- **users**: User accounts with email normalization and password hashing
- **oauth_clients**: OAuth 2.1 client registrations with PKCE support

### Token Tables

- **email_verification_tokens**: Email verification tokens with expiration
- **authorization_codes**: OAuth authorization codes with PKCE challenges
- **refresh_tokens**: Refresh tokens with rotation support

### Additional Tables

- **sessions**: User sessions (optional, can use Redis instead)
- **audit_logs**: Comprehensive audit logging for security events
- **roles**: Role-based access control (Phase 5+)
- **user_roles**: User-role assignments

### Key Features

- **UUIDv7 Primary Keys**: Time-ordered UUIDs for better index performance
- **JSONB Columns**: Flexible storage for metadata, policies, and arrays
- **PostgreSQL Enums**: Type-safe enums for grant types, response types, auth methods
- **Optimized Indexes**: Composite indexes, partial indexes for active records
- **Multi-tenancy**: All data scoped to realms for isolation

## Development

### Adding New Schemas

1. Create schema files in `src/lib/schema/`
2. Export them from `src/lib/schema/index.ts`
3. Generate migrations using `nx run db:db:generate`
4. Run migrations using `nx run db:db:migrate`

### Testing Database Connection

```typescript
import { testConnection } from '@qauth/db';

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

// Use Drizzle ORM via fastify.db
import { schema } from '@qauth/db';
const { users, oauthClients } = schema;

fastify.get('/users', async (request, reply) => {
  const allUsers = await fastify.db.select().from(users);
  return { users: allUsers };
});

// Or use connection pool directly
fastify.get('/health', async (request, reply) => {
  const result = await fastify.dbPool.query('SELECT NOW()');
  return { timestamp: result.rows[0].now };
});
```

The Fastify plugin automatically manages the database connection lifecycle, so you don't need to manually call `closeDatabase()` when using the plugin.

## Schema Design Principles

### Performance Optimizations

- **UUIDv7 Primary Keys**: Time-ordered UUIDs provide better B-tree index performance
- **BIGINT Timestamps**: Epoch milliseconds for efficient storage and queries
- **JSONB for Arrays**: Efficient storage and querying of arrays (grant_types, scopes, etc.)
- **Composite Indexes**: Optimized for common query patterns
- **Partial Indexes**: Index only active/valid records (e.g., `WHERE used = false`)

### Type Safety

- **PostgreSQL Enums**: Database-level validation for grant types, response types, auth methods
- **TypeScript Types**: Full type safety with Drizzle ORM
- **JSONB Types**: Typed JSONB columns for metadata and policies

### Security

- **Password Hashing**: Argon2id for user passwords and client secrets
- **Token Hashing**: SHA-256 hashes for refresh tokens (never store plain tokens)
- **Audit Logging**: Comprehensive logging of all security events
- **Multi-tenancy**: Complete data isolation between realms

## Future Enhancements

- Post-quantum cryptography key storage (Phase 7)
- Database seeding and fixtures
- Advanced query optimizations
- Read replicas support

## Related Libraries

- [`@qauth/fastify-plugin-db`](../../fastify-plugin/db/README.md): Fastify plugin wrapper for this library

## Dependencies

- `drizzle-orm`: TypeScript ORM for PostgreSQL
- `pg`: PostgreSQL client for Node.js
- `drizzle-kit`: Database toolkit and migration generator
- `dotenv`: Environment variable management

## License

Apache-2.0
