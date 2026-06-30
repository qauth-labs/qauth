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

`@qauth-labs/infra-db` exports a **factory**, not singletons. Call
`createDatabase(config)` to build a `{ db, pool, close, testConnection }`
instance, then pass `db` to the repository factories.

```typescript
import { createDatabase, schema } from '@qauth-labs/infra-db';

const database = createDatabase({
  connectionString: 'postgresql://user:pass@host:5432/db',
  pool: { max: 20, min: 2 },
});

const { users, oauthClients, realms } = schema;
const isConnected = await database.testConnection();

// Use the Drizzle client directly
const allUsers = await database.db.select().from(users);
const realm = await database.db.query.realms.findFirst({
  where: (realms, { eq }) => eq(realms.name, 'my-realm'),
});

// Create a new OAuth client
const [newClient] = await database.db
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

await database.close(); // graceful shutdown
```

> **Fastify app:** prefer the `@qauth-labs/fastify-plugin-db` plugin (below),
> which builds the database instance once and decorates
> `fastify.db` / `fastify.dbPool` / `fastify.repositories.*`. Route code should
> use those decorators rather than calling `createDatabase` directly.

### Repository Pattern

The library provides a repository pattern for type-safe database operations with
transaction support and proper error handling. Repositories are created via
**factory functions** that take the database client; there are **no singleton
repository exports**.

#### Using Repositories

```typescript
import { createDatabase } from '@qauth-labs/infra-db';
import {
  createUsersRepository,
  createEmailVerificationTokensRepository,
} from '@qauth-labs/infra-db';
import { NotFoundError, UniqueConstraintError } from '@qauth-labs/shared-errors';

const { db } = createDatabase({ connectionString: 'postgresql://…' });
const usersRepo = createUsersRepository(db);

// Create a new user
try {
  const user = await usersRepo.create({
    realmId: 'realm-123',
    email: 'user@example.com',
    passwordHash: 'argon2id_hash',
    emailVerified: false,
  });
  console.log('User created:', user);
} catch (error) {
  if (error instanceof UniqueConstraintError) {
    console.error('Email already exists:', error.constraint);
  }
  throw error;
}

// Find user by ID (throws NotFoundError if not found)
try {
  const user = await usersRepo.findByIdOrThrow('user-123');
} catch (error) {
  if (error instanceof NotFoundError) {
    console.error('User not found');
  }
}

// Find user by email (returns undefined if not found)
const user = await usersRepo.findByEmail('realm-123', 'user@example.com');

// Update / delete
const updatedUser = await usersRepo.update('user-123', { emailVerified: true });
const deleted = await usersRepo.delete('user-123');
```

#### Repository Factory Functions

Each repository is a factory taking a default database client (required):

```typescript
import { createDatabase } from '@qauth-labs/infra-db';
import { createUsersRepository, createRealmsRepository } from '@qauth-labs/infra-db';

const { db } = createDatabase({ connectionString: 'postgresql://…' });

const usersRepo = createUsersRepository(db);
const realmsRepo = createRealmsRepository(db);
```

#### Transaction Support

All repository methods accept an optional transaction client (`tx?`) that
overrides the default `db`. Drive transactions through the Drizzle client:

```typescript
const { db } = createDatabase({ connectionString: 'postgresql://…' });
const usersRepo = createUsersRepository(db);
const realmsRepo = createRealmsRepository(db);

await db.transaction(async (tx) => {
  const realm = await realmsRepo.create({ name: 'my-realm' }, tx);
  const user = await usersRepo.create(
    { realmId: realm.id, email: 'user@example.com', passwordHash: 'hash' },
    tx
  );
  return { realm, user }; // both commit, or both roll back
});
```

#### Available Repositories

Each factory takes a `defaultDb: DbClient`. Methods below take an optional
`tx?: DbClient`.

- **`createUsersRepository(db)`**: User CRUD
  - `create()`, `findById()`, `findByIdOrThrow()`, `findByEmail()`, `findByEmailNormalized()`, `update()`, `updateLastLogin()`, `verifyEmail()`, `delete()`
- **`createRealmsRepository(db)`**: Realm CRUD
  - `create()`, `findById()`, `findByIdOrThrow()`, `findByName()`, `update()`, `delete()`
- **`createOAuthClientsRepository(db)`**: OAuth client CRUD
  - `create()`, `findById()`, `findByIdOrThrow()`, `findByClientId()`, `listByDeveloper()`, `upsertCimdClient()`, `update()`, `delete()`
  - `listByDeveloper(developerId, tx?)`: lists a developer's own clients, scoped strictly by `developer_id` and ordered newest-first. Dynamically registered (RFC 7591 / DCR) clients carry a null `developer_id` and are excluded.
  - `upsertCimdClient(data, tx?)`: idempotent `INSERT ... ON CONFLICT` for Client ID Metadata Document (CIMD) clients keyed by `(realm_id, client_id)`. On conflict it refreshes only the document-derived fields (name, description, redirect URIs, grant/response types, auth method, metadata, enabled) and bumps `updatedAt`; identity columns and the secret sentinel are left untouched, so concurrent authorize requests for the same metadata-document `client_id` collapse onto a single row instead of racing a find-then-create.
- **`createApiKeysRepository(db)`**: Static developer API-key CRUD (ADR-008 §6)
- **`createAuditLogsRepository(db)`**: Audit-log operations
  - `create()`, `findByUserId()`, `findByRealmId()`, `findByRealmAndUserId()`, plus realm-isolated filters
- **`createAuthorizationCodesRepository(db)`**: Authorization code lifecycle
  - `create()`, `findByCode()`, `markUsed()`
- **`createRefreshTokensRepository(db)`**: Refresh-token lifecycle + family revocation
  - `create()`, `findByTokenHashIncludingRevoked()`, `revoke()`, `revokeFamily(familyId, reason)`
- **`createEmailVerificationTokensRepository(db)`**: Verification tokens
  - `create()`, `findByTokenHash()`, `markUsed()`, `deleteExpired()`

#### Error Handling

Repositories use error classes from `@qauth-labs/shared-errors` with HTTP status codes:

```typescript
import { createDatabase } from '@qauth-labs/infra-db';
import { createUsersRepository } from '@qauth-labs/infra-db';
import { NotFoundError, UniqueConstraintError } from '@qauth-labs/shared-errors';

const { db } = createDatabase({ connectionString: 'postgresql://…' });
const usersRepo = createUsersRepository(db);

try {
  const user = await usersRepo.findByIdOrThrow('invalid-id');
} catch (error) {
  if (error instanceof NotFoundError) {
    // Handle not found
    console.error(`Entity ${error.message}`);
    // error.statusCode === 404
  }
}

try {
  await usersRepo.create({
    realmId: 'realm-1',
    email: 'existing@example.com',
    passwordHash: '…',
  });
} catch (error) {
  if (error instanceof UniqueConstraintError) {
    // Handle unique constraint violation
    console.error(`Constraint violated: ${error.constraint}`);
    // error.statusCode === 409
  }
}
```

#### Audit Log Realm Filtering

For security and multi-tenancy, audit logs can be filtered by realm:

```typescript
import { createDatabase } from '@qauth-labs/infra-db';
import { createAuditLogsRepository } from '@qauth-labs/infra-db';

const { db } = createDatabase({ connectionString: 'postgresql://…' });
const auditLogsRepo = createAuditLogsRepository(db);

// Get all audit logs for a realm (security: ensures realm isolation)
const realmLogs = await auditLogsRepo.findByRealmId('realm-123', {
  limit: 50,
  eventType: 'auth',
  success: true,
});

// Get audit logs for a specific user within a realm
const userLogs = await auditLogsRepo.findByRealmAndUserId('realm-123', 'user-456', {
  limit: 20,
  descending: true,
});
```

**Security Note**: Realm filtering ensures that users can only access audit logs from their own realm, preventing cross-realm data leakage.

#### Base Repository Interface

All repositories follow a consistent interface defined in `BaseRepository`:

```typescript
import { BaseRepository } from '@qauth-labs/infra-db';

// BaseRepository provides a contract for common CRUD operations
interface BaseRepository<TSelect, TInsert, TUpdate> {
  create(data: TInsert, tx?: DbClient): Promise<TSelect>;
  findById(id: string, tx?: DbClient): Promise<TSelect | undefined>;
  findByIdOrThrow(id: string, tx?: DbClient): Promise<TSelect>;
  update(id: string, data: TUpdate, tx?: DbClient): Promise<TSelect>;
  delete(id: string, tx?: DbClient): Promise<boolean>;
}
```

This interface ensures consistency across all repositories and reduces code duplication.

### Connection Pool Management

Pool access comes from the instance returned by `createDatabase`, not a
singleton:

```typescript
import { createDatabase } from '@qauth-labs/infra-db';

const database = createDatabase({ connectionString: 'postgresql://…' });

// Direct pool access if needed
const client = await database.pool.connect();
try {
  const result = await client.query('SELECT NOW()');
  console.log(result.rows[0]);
} finally {
  client.release();
}

// Graceful shutdown
await database.close();
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

### Seeding

Two seeders live under `src/scripts/`. Both require `DATABASE_URL` in the environment (or in the repo-root `.env` — `dotenv` is loaded automatically).

```bash
# Dev fixture generator (destructive — calls reset() then replants realms + oauth_clients)
nx run db:db:seed

# Idempotent OAuth-client provisioner (additive; production-safe)
# Reads a JSON manifest; generates 32-byte client secrets; argon2id-hashes
# them; prints plaintext secrets once to STDOUT (the DB only keeps hashes).
# Existing client_ids are skipped unless `--rotate` is passed.
nx run db:db:seed-oauth-clients -- --manifest=/path/to/manifest.json [--rotate]
```

Manifest shape for `db:seed-oauth-clients`:

```json
{
  "realm": "default",
  "clients": [
    {
      "client_id": "example-service",
      "name": "Example Service",
      "grant_types": ["client_credentials"],
      "scopes": ["read:things"],
      "audience": ["https://api.example.com"]
    }
  ]
}
```

The target realm must already exist. See `src/scripts/seed-oauth-clients.ts` for the authoritative Zod schema and the full set of optional fields (`description`, `response_types`, `redirect_uris`, `require_pkce`, `token_endpoint_auth_method`).

## Project Structure

```
libs/infra/db/
├── src/
│   ├── lib/
│   │   ├── db.ts              # createDatabase factory + pool/Drizzle client
│   │   ├── repositories/      # Repository pattern implementations
│   │   │   ├── index.ts        # Factory exports
│   │   │   ├── base.repository.ts  # Base repository interface
│   │   │   ├── users.repository.ts
│   │   │   ├── realms.repository.ts
│   │   │   ├── oauth-clients.repository.ts
│   │   │   ├── oauth-consents.repository.ts
│   │   │   ├── refresh-tokens.repository.ts
│   │   │   ├── authorization-codes.repository.ts
│   │   │   ├── email-verification-tokens.repository.ts
│   │   │   ├── api-keys.repository.ts
│   │   │   ├── audit-logs.repository.ts
│   │   │   └── integration-setup.ts
│   │   ├── schema/
│   │   │   ├── index.ts        # Main schema exports
│   │   │   ├── core.ts         # Core tables: realms, users, oauth_clients, api_keys
│   │   │   ├── tokens.ts       # email_verification_tokens, authorization_codes, refresh_tokens
│   │   │   ├── consents.ts     # oauth_consents
│   │   │   ├── sessions.ts     # sessions (Phase 5+, currently unused — Redis holds sessions)
│   │   │   ├── audit.ts        # audit_logs (with agent attribution)
│   │   │   ├── roles.ts        # roles, user_roles (Phase 5+, currently unused)
│   │   │   ├── enums.ts        # PostgreSQL enum types
│   │   │   └── sql-helpers.ts  # EPOCH_MS_NOW, JSONB_EMPTY_ARRAY
│   │   └── types/              # Repository/database type definitions
│   ├── scripts/
│   │   ├── seed.ts                    # Dev-fixture seeder (drizzle-seed)
│   │   └── seed-oauth-clients.ts      # Idempotent client provisioner
│   ├── index.ts               # Public API: createDatabase, schema, factories, types
│   └── qauth-schema.dbml      # Database schema visualization (DBML format)
├── drizzle/                   # Migration files (0000_young_vermin.sql … 00NN)
│   └── meta/                  # Migration metadata / snapshots
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
4. Review the generated migration file in `drizzle/` directory
5. Run migrations using `nx run db:db:migrate`

### Schema Visualization

The database schema is available in DBML format at `src/qauth-schema.dbml`. You can:

- View it on [dbdiagram.io](https://dbdiagram.io) for visual representation
- Use it for documentation purposes
- Import it into database design tools

### Testing Database Connection

```typescript
import { createDatabase } from '@qauth-labs/infra-db';

const database = createDatabase({ connectionString: 'postgresql://…' });
const isConnected = await database.testConnection();
if (!isConnected) {
  throw new Error('Failed to connect to database');
}
```

## Fastify Integration

For Fastify applications, use the [`@qauth-labs/fastify-plugin-db`](../../fastify/plugins/db/README.md) plugin which wraps this library and provides:

- Automatic database connection lifecycle management
- Fastify instance decoration with `fastify.db` (Drizzle ORM) and `fastify.dbPool` (connection pool)
- Integration with Fastify's `onReady` and `onClose` hooks
- TypeScript type definitions for Fastify

**Example with Fastify**:

```typescript
import Fastify from 'fastify';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';

const fastify = Fastify();

// Register the database plugin
await fastify.register(databasePlugin);

// Use Drizzle ORM via fastify.db
import { schema } from '@qauth-labs/infra-db';
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

The Fastify plugin automatically manages the database connection lifecycle, so you don't need to manually call `database.close()` when using the plugin.

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
- Advanced query optimizations
- Read replicas support

## Related Libraries

- [`@qauth-labs/shared-errors`](../../shared/errors/README.md): Error classes used by repositories
- [`@qauth-labs/fastify-plugin-db`](../../fastify/plugins/db/README.md): Fastify plugin wrapper for this library

## Dependencies

- `drizzle-orm`: TypeScript ORM for PostgreSQL
- `pg`: PostgreSQL client for Node.js
- `drizzle-kit`: Database toolkit and migration generator
- `dotenv`: Environment variable management

## License

Apache-2.0
