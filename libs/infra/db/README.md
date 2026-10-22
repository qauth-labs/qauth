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
  createUserCredentialsRepository,
  createUserAttributesRepository,
} from '@qauth-labs/infra-db';
import { buildPasswordCredentialData, selectTrustedAttribute } from '@qauth-labs/server-federation';
import { NotFoundError, UniqueConstraintError } from '@qauth-labs/shared-errors';

const { db } = createDatabase({ connectionString: 'postgresql://…' });
const usersRepo = createUsersRepository(db);
const credentialsRepo = createUserCredentialsRepository(db);
const attributesRepo = createUserAttributesRepository(db);

// Registration is two writes, in one transaction: the identity anchor, then
// the credential. `users` carries no email or password (ADR-002 / #230).
try {
  const user = await usersRepo.create({ realmId: 'realm-123' });

  await credentialsRepo.create({
    userId: user.id,
    realmId: 'realm-123',
    providerType: 'password',
    // The normalized email — the duplicate-registration guard is the
    // (realm_id, provider_type, external_sub) unique index on this row.
    externalSub: 'user@example.com',
    // Keys are snake_case and load-bearing: the login path reads
    // `credential_data.password_hash`. Build it with the canonical helper
    // rather than by hand — `buildPasswordCredentialData(hash, emailVerified)`
    // from @qauth-labs/server-federation returns
    // `{ password_hash, email_verified }`.
    credentialData: buildPasswordCredentialData('argon2id_hash', false),
  });
} catch (error) {
  if (error instanceof UniqueConstraintError) {
    console.error('Credential already registered:', error.constraint);
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

// Look an account up by its credential — this replaces the old findByEmail()
const credential = await credentialsRepo.findByRealmProviderSub(
  'realm-123',
  'password',
  'user@example.com'
);

// Fetch every VERIFIED row for a claim. This returns an ARRAY and applies no
// ordering — the ADR-002 trust order lives in application code, not in SQL.
const rows = await attributesRepo.findVerifiedByUserIdAndKey('user-123', 'email');

// Rank them with @qauth-labs/server-federation (wallet > oidc_* > self_reported)
const email = selectTrustedAttribute(rows);

// Update / delete
const updatedUser = await usersRepo.update('user-123', { enabled: false });
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
  // `users` takes no email/password — see the registration example above.
  const user = await usersRepo.create({ realmId: realm.id }, tx);
  await credentialsRepo.create(
    {
      userId: user.id,
      realmId: realm.id,
      providerType: 'password',
      externalSub: 'user@example.com',
      credentialData: buildPasswordCredentialData('hash', false),
    },
    tx
  );
  return { realm, user }; // both commit, or both roll back
});
```

#### Available Repositories

Each factory takes a `defaultDb: DbClient`. Methods below take an optional
`tx?: DbClient`.

- **`createUsersRepository(db)`**: Identity-anchor CRUD
  - `create()`, `findById()`, `findByIdOrThrow()`, `update()`, `updateLastLogin()`, `delete()`
  - Since ADR-002 / #230 the `users` table carries **no email or password columns**, so there is no `findByEmail()`, `findByEmailNormalized()` or `verifyEmail()`. Look an account up through `createUserCredentialsRepository(db).findByRealmProviderSub()` instead; duplicate registration is guarded by the credentials unique index, not by this insert.
- **`createUserCredentialsRepository(db)`**: Credential rows per authentication method (ADR-002 / ADR-003)
  - `create()`, `findById()`, `findByRealmProviderSub()`, `findByUserIdAndType()`, `findAllByUserIdAndType()`, `findAllByRealmAndExternalSub()`, `updateCredentialData()`, `setEmailVerified()`
  - `findByRealmProviderSub(realmId, providerType, externalSub)` is the credential lookup that replaces the removed `findByEmail()`. It is not itself the duplicate guard — duplicates are caught by the `(realm_id, provider_type, external_sub)` **unique index**, which raises on insert even if this lookup is skipped or races.
- **`createUserAttributesRepository(db)`**: Normalized claims per user (ADR-002)
  - `upsertMany()`, `findVerifiedByUserIdAndKey()`, `setVerified()`
  - `findVerifiedByUserIdAndKey()` returns **every verified row** for that key as an array, in no particular order. It does **not** rank them — the ADR-002 trust order (`wallet > oidc_* > self_reported`) is enforced in application code by `rankAttributeSource()` / `selectTrustedAttribute()` in `libs/server/federation/src/claims/attribute-trust.ts`. Pair the two to resolve the `email` / `email_verified` claims.
- **`createOAuthConsentsRepository(db)`**: Consent grants and revocation
- **`createOid4vpRequestStatesRepository(db)`**: OID4VP request/response correlation (T4)
  - Realm-scoped, unique `state_hash`, single-use via `redeemed_at`. Unused unless `WALLET_FEDERATION_ENABLED` is on.
- **`createRealmKeysRepository(db)`**: Per-realm, per-purpose keys, envelope-encrypted (ADR-019 Decision 9)
  - `create()`, `findByKid()`, `listByRealm()`, `getWrappedForSigner()`
  - `create({ key, publicJwk? })` writes the `realm_keys` row and, for a published purpose, its `realm_public_keys` row in one transaction, copying the mirror columns from the key row.
  - `getWrappedForSigner(realmId, kid)` is the **only** method that returns `ciphertext`, `iv` and `wrapped_dek`. Every other method returns a `RealmKey` without them; a unit test fails when another method selects one.
- **`createRealmsRepository(db)`**: Realm CRUD, and the realm's hosts (ADR-019 Decision 1)
  - `create()`, `findById()`, `findByIdOrThrow()`, `findByName()`, `update()`, `delete()`
  - `findByHost(host)`, `createWithPrimaryHost(data, host)`, `addEndpointHost(realmId, host)`, `removeEndpointHost(realmId, host)`
  - Every host goes through `normaliseRealmHost()` from `@qauth-labs/shared-validation` (lower case, punycode, no port, no trailing dot), so any spelling of a stored host finds it and a host is stored only once. `findByHost` returns `{ realm, host }` and matches nothing for a value that cannot be a host. A duplicate host, of either kind and in any realm, is a `UniqueConstraintError` on `realm_hosts_pkey`.
  - `createWithPrimaryHost` writes the realm and its primary host in one transaction. The issuer is required and must sit on the primary host; a primary host is never an IP literal.
  - An issuer is an `https` URL; plain `http` is accepted only on `localhost` or a name under it, for development. It holds no white space, control character or backslash, which the URL parser would drop or rewrite. Both rules are CHECKs on `realms.issuer` (`realms_issuer_scheme`, `realms_issuer_no_space_or_control`), so they also hold for an issuer set by `update`.
  - A realm's `issuer` and primary host are **permanent**: database triggers allow them to be set once, from nothing, and refuse every later change (SQLSTATE 23514, constraints `realms_issuer_permanent` and `realm_hosts_primary_permanent`). Deleting the realm still removes its hosts. The triggers are hand-written SQL in migration 0025, which `drizzle-kit push` does not create; use the migrations.
  - At most one realm has `isOperator: true` (`idx_realms_one_operator`).
- **`createOAuthClientsRepository(db)`**: OAuth client CRUD
  - `create()`, `findById()`, `findByIdOrThrow()`, `findByClientId()`, `listByDeveloper()`, `upsertCimdClient()`, `update()`, `delete()`
  - `listByDeveloper(developerId, tx?)`: lists a developer's own clients, scoped strictly by `developer_id` and ordered newest-first. Dynamically registered (RFC 7591 / DCR) clients carry a null `developer_id` and are excluded.
  - `upsertCimdClient(data, tx?)`: idempotent `INSERT ... ON CONFLICT` for Client ID Metadata Document (CIMD) clients keyed by `(realm_id, client_id)`. On conflict it refreshes only the document-derived fields (name, description, redirect URIs, grant/response types, auth method, key set, metadata), can only narrow `enabled`, never names `suspended`, writes `provisioned_by_operator = false` (a CIMD client is never operator-provisioned) and bumps `updatedAt`; identity columns and the secret sentinel are left untouched, so concurrent authorize requests for the same metadata-document `client_id` collapse onto a single row instead of racing a find-then-create.
- **`createApiKeysRepository(db)`**: Static developer API-key CRUD (ADR-008 §6)
- **`createAuditLogsRepository(db)`**: Audit-log operations
  - `create()`, `findByUserId()`, `findByRealmId()`, `findByRealmAndUserId()`, plus realm-isolated filters
- **`createAdminAuditLogRepository(db, options?)`**: The append-only admin audit log (ADR-019 Decision 7, #448). It takes the root database, not a `DbClient`, because verification opens its own transaction.
  - `appendAdminAudit(tx, entry)` needs the caller's transaction (a `DbTransaction`, not the root database), so the row commits or rolls back with the change it records. It takes the target realm's chain lock (`pg_advisory_xact_lock`), masks the diff with `maskSecrets(change, annotations)` and appends the next row of the realm's chain. `options.afterAppend(tx, record)` runs right after the insert, in the same transaction; it is the hook for the event outbox writer.
  - `verifyAdminAuditChain(realmId)` checks the chain from the oldest retained row, anchored on the newest checkpoint after a prune, and returns the first row that breaks it (`sequence_mismatch`, `prev_hash_mismatch` or `row_hash_mismatch`).
  - `row_hash` is SHA-256 over `prev_hash` and the RFC 8785 canonical JSON (`canonicalizeJson`) of the row's other columns, under their column names (`computeAdminAuditRowHash`). The first row's `prev_hash` is 32 zero bytes.
  - A secret field is stored as `ADMIN_AUDIT_SECRET_MARKER`, never as a value. Annotate every secret a diff can carry, a set-up or reset link, code or token included.
  - Triggers in migration 0026 hold for every role whose statements fire them (SQLSTATE 23514, the constraint named): an inserted row must follow the realm's chain head (`admin_audit_log_follows_head`); no row is updated and neither table is truncated (`admin_audit_log_append_only`, `admin_audit_log_checkpoints_append_only`); a row is deleted only when a checkpoint covers it; a checkpoint names a row still in the log with its hash (`admin_audit_log_checkpoints_match`), moves forward (`admin_audit_log_checkpoints_forward`), covers an unbroken, linked run of rows (`admin_audit_log_checkpoints_unbroken`) and none younger than 90 days (`admin_audit_log_retention_floor`). The retention job removes rows with `SELECT admin_audit_log_prune(realm_id, through_seq)`, which writes the checkpoint and deletes the realm's rows up to that `seq`; `EXECUTE` on it is revoked from `PUBLIC`. Run `verifyAdminAuditChain` before a prune: the database checks the links, not the row hashes. A table owner or a superuser can disable a trigger, so only the per-role grants (#498) protect the log from the application's own database user. The triggers are hand-written SQL, which `drizzle-kit push` does not create; use the migrations.
  - The hash is unkeyed: a party that can rewrite a row and every row after it, or cut the newest rows, leaves a chain that verifies. A copy of each head kept outside the database, such as the outbox event that mirrors the row with its `seq` and `row_hash`, is what shows that.
  - `adminAuditLogWriterGrantStatements(role)` returns the statements that give a writing role `INSERT` and `SELECT` on the log and `SELECT` on the checkpoints, and nothing else. The per-role grants script (#498) applies them.
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
  // The unique index lives on `user_credentials`, so this is the write that
  // raises on a duplicate registration — not the `users` insert.
  await credentialsRepo.create({
    userId: 'user-123',
    realmId: 'realm-1',
    providerType: 'password',
    externalSub: 'existing@example.com',
    credentialData: buildPasswordCredentialData('…', false),
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

# Operator-only suspension of one client (or --lift to end it)
nx run db:db:suspend-oauth-client -- --realm=<realm name> --client-id=<client_id> [--lift]
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

Both seeders mark their clients `provisioned_by_operator = true`, and so does the system client the auth-server creates for its own login. Only such a client receives authorization error responses by automatic redirect (RFC 9700 §4.11.2); every client created through `POST /oauth/register`, a CIMD document or `POST /api/clients` gets them on an issuer page. A `--rotate` run sets the marker on the clients it rewrites, which is how an operator marks a client that migration 0023's backfill left unmarked.

`oauth_clients.enabled` is the client owner's switch: `PATCH /api/clients/:id` may set it either way. An operator who must keep a client off **suspends** it instead (`oauth_clients.suspended`, `suspended_at`). A suspended client is refused wherever a disabled one is, no route writes the column, and a CIMD re-resolution never touches it. `db:suspend-oauth-client` sets or lifts it in one transaction with an `oauth.client.suspended` / `oauth.client.suspension_lifted` audit row; the equivalent by hand is `UPDATE oauth_clients SET suspended = true, suspended_at = <epoch ms> WHERE client_id = '<client_id>'`. Lifting a suspension leaves `enabled` as it is. Migration 0023 suspends every client that was disabled when it ran, since the row does not record whether the operator or the owner disabled it.

## Project Structure

```
libs/infra/db/
├── src/
│   ├── lib/
│   │   ├── db.ts              # createDatabase factory + pool/Drizzle client
│   │   ├── admin-audit/       # canonicalizeJson (RFC 8785), maskSecrets, row hash, grants
│   │   ├── repositories/      # Repository pattern implementations
│   │   │   ├── index.ts        # Factory exports
│   │   │   ├── base.repository.ts  # Base repository interface
│   │   │   ├── admin-audit-log.repository.ts  # admin_audit_log (append-only, hash-chained)
│   │   │   ├── users.repository.ts
│   │   │   ├── realms.repository.ts
│   │   │   ├── oauth-clients.repository.ts
│   │   │   ├── oauth-consents.repository.ts
│   │   │   ├── refresh-tokens.repository.ts
│   │   │   ├── authorization-codes.repository.ts
│   │   │   ├── email-verification-tokens.repository.ts
│   │   │   ├── api-keys.repository.ts
│   │   │   ├── audit-logs.repository.ts
│   │   │   ├── realm-keys.repository.ts  # realm_keys / realm_public_keys (signer only)
│   │   │   └── integration-setup.ts
│   │   ├── schema/
│   │   │   ├── index.ts        # Main schema exports
│   │   │   ├── core.ts         # Core tables: realms, users, oauth_clients, api_keys
│   │   │   ├── tokens.ts       # email_verification_tokens, authorization_codes, refresh_tokens
│   │   │   ├── consents.ts     # oauth_consents
│   │   │   ├── sessions.ts     # sessions (Phase 5+, currently unused — Redis holds sessions)
│   │   │   ├── audit.ts        # audit_logs (with agent attribution)
│   │   │   ├── admin-audit.ts  # admin_audit_log, admin_audit_log_checkpoints (ADR-019 Decision 7)
│   │   │   ├── roles.ts        # roles, user_roles (Phase 5+, currently unused)
│   │   │   ├── keys.ts         # realm_keys, realm_public_keys (ADR-019 Decision 9)
│   │   │   ├── enums.ts        # PostgreSQL enum types
│   │   │   └── sql-helpers.ts  # EPOCH_MS_NOW, JSONB_EMPTY_ARRAY, bytea
│   │   └── types/              # Repository/database type definitions
│   ├── scripts/
│   │   ├── seed.ts                    # Dev-fixture seeder (drizzle-seed)
│   │   ├── seed-oauth-clients.ts      # Idempotent client provisioner
│   │   ├── client-suspension.ts       # Operator suspension logic
│   │   └── suspend-oauth-client.ts    # Operator suspension CLI
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
- **users**: Pure identity anchor. Since migration 0011 (ADR-002, #230) it carries **no** `email`, `email_normalized` or `password_hash` — all credential data lives in `user_credentials`
- **user_credentials**: One row per authentication method per user (`password`, `wallet`, …), keyed by `(realm_id, provider_type, external_sub)` — the sole duplicate-registration guard
- **user_attributes**: Normalized claims (email, name, …) with a source and verification state; resolved in the ADR-002 trust order `wallet > oidc_* > self_reported`
- **oauth_clients**: OAuth 2.1 client registrations with PKCE support

### Token Tables

- **email_verification_tokens**: Email verification tokens with expiration, pointed at a `credential_id`
- **authorization_codes**: OAuth authorization codes with PKCE challenges, plus `auth_time` (0013) and `assurance_level` (0016, ADR-010)
- **refresh_tokens**: Refresh tokens with rotation support

### Federation Tables (T4)

- **oid4vp_request_states**: OID4VP request/response correlation — realm-scoped, unique `state_hash`, a DCQL query, expiry and single-use `redeemed_at`. Unused unless `WALLET_FEDERATION_ENABLED` is on

### Key Tables (ADR-019 Decision 9)

- **realm_keys**: Each realm's keys, one row per key, per purpose and (for webhook and upstream client-assertion keys) per `scope_id`. The material is stored envelope-encrypted (`ciphertext`, `iv`, `wrapped_dek`, with `kek_ref` naming the KEK and `aad_version` the associated-data layout). `status` is `next`, `active`, `retired` or `compromised`; a partial unique index allows one `active` key per realm, purpose, scope and algorithm, and `kid` is unique per realm. Only the signer's database user may read it once the per-role grants (#498) are applied
- **realm_public_keys**: The public JWK of every published key, keyed by `(realm_id, kid)`. Its foreign key to the `realm_keys` row covers `purpose`, `algorithm` and `status` with `ON UPDATE CASCADE`, so a status change on the key row (a compromise included) reaches the public row in the same statement; change the status on `realm_keys` only. Every role may read it for the JWKS and for verification. Symmetric purposes have no row here: CHECKs require a `kty` other than `oct` and refuse private JWK members

### Admin Audit Tables (ADR-019 Decision 7)

- **admin_audit_log**: One row per admin operation, written in the transaction of the change. Keyed by `(realm_id, seq)`: one hash chain per target realm, `seq` from 1 without a gap, each row carrying the previous row's hash (`prev_hash`) and its own (`row_hash`). It records the actor kind (`human_admin`, `service_account`, `break_glass_operator`, `host_operator`), the actor and the actor's realm, the full act chain when the actor acted for a user, the operation id and class, its effects and outcome, the diff with secrets masked, the approvals, the request digest, the trace id and the time. No foreign keys: a realm's record outlives the realm row. Append-only by trigger; a writing role is granted `INSERT` and `SELECT` only
- **admin_audit_log_checkpoints**: The `seq` and `row_hash` of the last row each prune removed, so the oldest retained row still verifies. Written by `admin_audit_log_prune()`; a trigger accepts a checkpoint only over an unbroken run of rows at least 90 days old. Append-only too

### Additional Tables

- **sessions**: User sessions (optional, can use Redis instead)
- **audit_logs**: Comprehensive audit logging for security events
- **api_keys**: Environment-gated static developer API keys (ADR-008 §6)
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
