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
- **`createOid4vpRequestStatesRepository(db)`**: OID4VP request/response correlation
  - Realm-scoped, unique `state_hash`, single-use via `redeemed_at`. Unused unless `WALLET_FEDERATION_ENABLED` is on.
- **`createRealmKeysRepository(db)`**: Per-realm, per-purpose keys, envelope-encrypted (ADR-019 Decision 9)
  - `create()`, `findByKid()`, `listByRealm()`, `listPublicByRealm()`, `getWrappedForSigner()`, `updateStatus()`, `deleteByScope()`, `lockRealm(realmId, tx)`
  - `create({ key, publicJwk? })` writes the `realm_keys` row and, for a published purpose, its `realm_public_keys` row in one transaction, copying the mirror columns from the key row.
  - `updateStatus(realmId, kid, change)` moves one key a rotation step, `next` → `active` or `active` → `retired`, and only from that status. The status reaches the public row through its foreign key; a retirement also writes the public row's `unpublish_at`.
  - `deleteByScope(realmId, purpose, scopeId)` deletes the keys of one webhook subscription or upstream provider, with their public rows. It never matches an unscoped key.
  - `getWrappedForSigner(realmId, kid)` is the **only** method that returns `ciphertext`, `iv` and `wrapped_dek`. Every other method returns a `RealmKey` without them; a unit test fails when another method selects one.
  - `lockRealm(realmId, tx)` takes a transaction-scoped advisory lock on one realm's keys. The key boot step (#485) holds it, so nodes that start together import and create a realm's keys one at a time.
- **`createSessionsRepository(db)`**: Browser sessions (ADR-019 Decision 3, #468)
  - `create()`, `findById(realmId, id)`, `updateLastSeen(realmId, id, { minIntervalMs? })`, `revoke(realmId, id, reason)`, `listActiveForUser(realmId, userId)`
  - Every method that names a session or a user takes the realm id too, and its statement filters on it; a unit test fails when one stops doing so. A session of another realm is never found, touched, ended or listed. The database adds the rest: the composite foreign key `sessions_user_realm_fk` refuses a session whose realm is not its user's.
  - `create` leaves the id to the database (`uuidv7()`); it is the session's `sid`. `findById` returns the row whatever its state, for the session service to judge. `updateLastSeen` is one conditional `UPDATE` on a live row seen at least `minIntervalMs` ago, so nodes touching one session within the interval write once. `revoke` ends a session not yet revoked and returns it; a second call returns `undefined` and keeps the first reason.
- **`createRealmsRepository(db)`**: Realm CRUD, and the realm's hosts (ADR-019 Decision 1)
  - `create()`, `findById()`, `findByIdOrThrow()`, `findByName()`, `update()`, `delete()`
  - `findByHost(host)`, `createWithPrimaryHost(data, host)`, `assignIssuer(realmId, issuer, host)`, `addEndpointHost(realmId, host)`, `removeEndpointHost(realmId, host)`, `findOperator()`, `lockProvisioning(tx)`
  - Every host goes through `normaliseRealmHost()` from `@qauth-labs/shared-validation` (lower case, punycode, no port, no trailing dot), so any spelling of a stored host finds it and a host is stored only once. `findByHost` returns `{ realm, host }` and matches nothing for a value that cannot be a host. A duplicate host, of either kind and in any realm, is a `UniqueConstraintError` on `realm_hosts_pkey`.
  - `createWithPrimaryHost` writes the realm and its primary host in one transaction. The issuer is required and must sit on the primary host; a primary host is never an IP literal.
  - `assignIssuer` gives an existing realm, such as one from before migration 0025, its issuer and primary host in one transaction, under the same rules. Each is written only where the realm has none, so a second call with the same values changes nothing; a different issuer or primary host is a `BadRequestError`.
  - `lockProvisioning(tx)` takes a transaction-scoped advisory lock. The auth-server's default realm boot step (#484) holds it, so nodes that start together provision the realm one at a time.
  - An issuer is an `https` URL; plain `http` is accepted only on `localhost` or a name under it, for development. It holds no white space, control character or backslash, which the URL parser would drop or rewrite. Both rules are CHECKs on `realms.issuer` (`realms_issuer_scheme`, `realms_issuer_no_space_or_control`), so they also hold for an issuer set by `update`.
  - A realm's `issuer` and primary host are **permanent**: database triggers allow them to be set once, from nothing, and refuse every later change (SQLSTATE 23514, constraints `realms_issuer_permanent` and `realm_hosts_primary_permanent`). Deleting the realm still removes its hosts. The triggers are hand-written SQL in migration 0025, which `drizzle-kit push` does not create; use the migrations.
  - At most one realm has `isOperator: true` (`idx_realms_one_operator`).
  - The passkey RP ID (ADR-019 Decision 2, #467, #553) is two columns: `webauthn_rp_id`, NULL for the realm's primary host or an opted-in parent domain, and `webauthn_rp_id_locked_at`, the lock. `resolveRpId(realm)` from `@qauth-labs/shared-validation` gives the RP ID, never with a port.
  - `setWebAuthnRpId(realmId, rpId | null, tx?)` writes the setting while the realm is unlocked. The caller checks the value with the WebAuthn provider's rules (`resolveRelyingPartyId`: the `allowParentDomainRpId` opt-in, the label boundary, the Public Suffix List); this method refuses only a value that is not a host name, an IP literal, or a name that is not the primary host or a parent of it (`BadRequestError`). On a locked realm a value naming the locked RP ID changes nothing and any other is a `BadRequestError`. The auth-server's boot step stores `WEBAUTHN_RP_ID` through it.
  - `lockRpIdForEnrolment(tx, realmId)` sets `webauthn_rp_id_locked_at` where it is empty and returns `{ rpId, lockedAt, lockedNow }`, the RP ID to store the passkey under. The passkey enrolment calls it in the transaction that stores the credential, so the first passkey and the lock commit together. Two first enrolments that race lock once and get the same RP ID; once locked, a call takes no row lock. From the lock on, the trigger `realms_webauthn_rp_id_locked` (migration 0034) refuses any change of `webauthn_rp_id` or of the lock itself (SQLSTATE 23514), whoever writes it.
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
  - `row_hash` is SHA-256 over the chain format's id, `qauth-admin-audit-chain/1-rc.0` (a release candidate until 1.0.0, ADR-018 §5), and a NUL byte, `prev_hash`, and the RFC 8785 canonical JSON (`canonicalizeJson`) of the row's other columns, under their column names (`computeAdminAuditRowHash`). The first row's `prev_hash` is 32 zero bytes.
  - A secret field is stored as `ADMIN_AUDIT_SECRET_MARKER`, never as a value. Annotate every secret a diff can carry, a set-up or reset link, code or token included.
  - Triggers in migration 0026 hold for every role whose statements fire them (SQLSTATE 23514, the constraint named): an inserted row must follow the realm's chain head (`admin_audit_log_follows_head`); no row is updated and neither table is truncated (`admin_audit_log_append_only`, `admin_audit_log_checkpoints_append_only`); a row is deleted only when a checkpoint covers it; a checkpoint names a row still in the log with its hash (`admin_audit_log_checkpoints_match`), moves forward (`admin_audit_log_checkpoints_forward`), covers an unbroken, linked run of rows (`admin_audit_log_checkpoints_unbroken`) and none younger than 90 days (`admin_audit_log_retention_floor`). The retention job removes rows with `SELECT admin_audit_log_prune(realm_id, through_seq)`, which writes the checkpoint and deletes the realm's rows up to that `seq`; `EXECUTE` on it is revoked from `PUBLIC`. Run `verifyAdminAuditChain` before a prune: the database checks the links, not the row hashes. A table owner or a superuser can disable a trigger, so only the per-role grants (#498) protect the log from the application's own database user. The triggers are hand-written SQL, which `drizzle-kit push` does not create; use the migrations.
  - The hash is unkeyed: a party that can rewrite a row and every row after it, or cut the newest rows, leaves a chain that verifies. A copy of each head kept outside the database, such as the outbox event that mirrors the row with its `seq` and `row_hash`, is what shows that.
  - `adminAuditLogWriterGrantStatements(role)` returns the statements that give a writing role `INSERT` and `SELECT` on the log and `SELECT` on the checkpoints, and nothing else. The per-role grants script that will apply them (#498) is not built yet.
- **`createEventsRepository(db, options?)`**: The event store (ADR-019 Decision 8, #457): the transactional outbox and the event log in one append-only table, `events`. It takes the root database, which reads and `emitInOwnTransaction` use. See [Event store](#event-store) for the write rule, the read rule and the lag.
  - `emit(tx, event)` writes one event in the caller's transaction (a `DbTransaction`, not the root database) and returns its id. It checks the event with `parseEvent` from `@qauth-labs/shared-events` first and throws `EventValidationError` on an unknown type, a payload that fails its schema or the payload rules, or a NUL character; nothing is written then. The repository makes the id (a UUIDv7) and the time, and takes the category from the registry. The insert reads nothing back, so a role granted only `INSERT` on `events` can write.
  - `emitInOwnTransaction(event)` is the same for a caller without a transaction: one `INSERT`, a transaction of its own.
  - `emitAdminEvent(tx, { realm, actor, operation, target, before, after, secretFields?, approvals?, client?, request? })` records one admin change as an `admin.change_applied` event in the caller's transaction (#459). It builds the diff from `before` and `after` with `buildAdminDiff` from `@qauth-labs/shared-events`: changed fields only, nested objects diffed, arrays whole, every secret field `***`. A command-line tool on the server host passes `operatorCliActor()`, which names the operating-system user.
  - An event of an `admin` type joins its realm's hash chain, whichever call writes it. See [Admin events and the hash chain](#admin-events-and-the-hash-chain).
  - `verifyChain(realmId, from?)` checks the realm's admin chain after `from` (by default the realm's retention anchor, or the chain's start before retention has deleted an admin row) and returns `{ ok: true, head }` or `{ ok: false, break: { id, seq, reason } }` for the first admin event that does not verify. `pnpm --dir libs/infra/db exec tsx src/scripts/verify-event-chain.ts --realm=<name>` runs it from the command line, and exits 0 when the chain verifies, 1 when it breaks, 2 on a usage error and 3 when the check could not run: the database unreachable or failing, or no realm and no event with the realm given (#827). The Nx target `infra-db:events:verify-chain` runs the same script, but Nx reports every failure as 1.
  - `readAfter(realmId, position, limit, filters?)` returns `{ events, next }`: the realm's events after `position`, oldest first in `(xid, seq)` order, at most `limit` (1 to 1000), each with its own `position`. `filters` narrows by `types`, `category`, `subjectId`, `clientId` and `fromTime`. Read on from `next`.
  - `oldestUnreadEventAge()` returns how long, in seconds, the oldest committed event has been held back from readers. It returns no event, so it takes no realm.
  - A position (`EventPosition`) is opaque text that names its realm, `xid` and `seq`. Start a realm's stream with `eventStreamStart(realmId)`. A position of another realm, or one that does not parse, throws `EventPositionError`.
- **`createEventDeliveriesRepository(db)`**: The delivery queue of the delivery role (ADR-019 Decision 8, #460): one `event_deliveries` row per destination and event. See [Event delivery](#event-delivery).
  - `fanOut({ kinds, destinations, now })` writes the rows for the events after each position, one per realm and route kind, and moves the position on, one stream at a time per node. It touches only the positions of the `kinds` the caller serves.
  - `dueDestinations(kinds, now)`, `claim({ picks, now, leaseMs, maxAttempts })`, `record(claim, outcome, now)` and `release(claims, now)` run the claims.
  - `minOffered(realmId)` returns the lowest position every destination has finished, for the retention job (#536).
- **`createSsfStreamsRepository(db)`**: The streams of the Shared Signals Framework transmitter (#410): `ssf_streams`, one per receiver and realm, and the subjects each receiver added (`ssf_stream_subjects`).
  - `create`, `find`, `list`, `update`, `remove` and `setStatus` name the realm and the receiver's client row, so a receiver reaches only its own stream; `create` returns `null` when the receiver already has one.
  - `addSubject(streamId, subject, maxSubjects)` returns `added`, `present`, `full`, or `missing` for a stream deleted meanwhile (the count and the insert run under the stream's row lock); `removeSubject` and `listSubjects` complete the set.
  - `listDestinations()` and `findForDelivery(streamId)` serve the SSF delivery route: streams of active receivers in realms whose `ssf_transmitter_enabled` is on, with the event store subjects of their subjects. `deliveryStatus(streamId, now)` reads the pending deliveries and the latest failed attempt, leaving out a row an attempt is running on.
  - `enqueueForEvent(tx, { streamId, eventId, now })` writes the delivery of an event addressed to one stream (a verification event) in the transaction that wrote the event, for a stream of the event's realm only.
  - `pendingByKind()` and `deliveryLagSeconds(now)` feed the metrics; `listForEvent(eventId)` returns an event's deliveries.
- **`createEventRetentionRepository(db)`**: The retention job's access to the event store (ADR-020 §3, #536). It needs the retention role's grants (`eventRetentionGrantStatements`), the only `DELETE` on `events`.
  - `realms(fallback)` lists every realm that has events with its retention from the realm row, or `fallback` for a realm whose row is gone.
  - `offeredThrough(realmId, served?)` is `minOffered` with the destinations a node knows to be enabled: for a route kind in `served.kinds`, a destination that is not listed (disabled) holds nothing back; a kind not listed counts in full.
  - `deleteBatch({ realmId, category, before, through, limit, now })` deletes one batch of the realm's oldest rows of one category, older than `before` and at or before `through`, in a short transaction under the realm's retention lock (`busy` when another instance holds it). Admin rows go only from the start of the chain, never its head, and only while each verifies; the last one deleted becomes the realm's anchor in `event_chain_anchors`, in the same transaction, and a row that breaks the chain stays (`chainBreak`).
  - `oldestEventTimes()` returns the time of each category's oldest event, for the `qauth_events_oldest_age_seconds` gauge.
- **`createAuthorizationCodesRepository(db)`**: Authorization code lifecycle
  - `create()`, `findByCode()`, `findByCodeIncludingUsed()` (spent and expired codes too, so a second redemption is recognised as a replay), `markUsed()`
- **`createRefreshTokensRepository(db)`**: Refresh-token lifecycle + family revocation
  - `create()`, `findByTokenHashIncludingRevoked()`, `revoke()`, `revokeFamily(familyId, reason)`, `revokeFamilyByAuthorizationCode(codeId, reason, tx?)` (the family whose first token carries `authorization_code_id`; returns `{ familyId, revokedCount }`)
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

`audit_logs` is read-only since #458: the auth server records events in the
[event store](#event-store), and migration 0031 copied every audit row there.
The table and its repository stay until a contract migration drops them after
one release; until then its rows can still be read, filtered by realm:

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

#### Event Store

The `events` table (migration 0029) is both the transactional outbox and the
event log (ADR-019 Decision 8). Each row is one envelope of the event contract
(`@qauth-labs/shared-events`), plus `seq` (an identity) and `xid` (the writing
transaction's id, `pg_current_xact_id()`).

**The write rule.** An event is written in the transaction of the change it
records, so both commit or neither does. A caller that has a transaction
passes it to `emit`. A caller without one, such as a change that is a single
statement or an event that records no change, calls `emitInOwnTransaction`,
which writes the event in a short transaction of its own. Never emit after the
change's transaction has committed: the change would stay and the event could
be lost.

The auth server does not call the repository directly: its routes call
`emitUserEvent` (`apps/auth-server/src/app/helpers/user-events.ts`, #458),
which fills the realm, the request, the subject, the client and the actor, and
passes the route's transaction when it has one.

**The audit log's rows.** Migration 0031 copied every `audit_logs` row into
`events`: the type from `LEGACY_EVENT_MAP`, the type's category, `created_at`
as the time, the realm of the row's user, else its client, else the one its
metadata names, else the operator realm. `data` holds only the members the
type declares, and a required member an old row could not supply gets a fixed
value (`unknown`, `false`, `[]`, `0` or the nil UUID). The copy is idempotent.

```typescript
import { createEventsRepository, eventStreamStart } from '@qauth-labs/infra-db';

const events = createEventsRepository(db);

// Sign-out: the tokens are revoked and the event recorded, or neither.
await db.transaction(async (tx) => {
  await refreshTokensRepo.revokeAllForUser(userId, 'logout', tx);
  await events.emit(tx, {
    type: 'urn:qauth:event:user.signed_out:v1-rc.0',
    realm: realmId,
    actor: { type: 'user', id: userId },
    subject: { type: 'user', id: userId },
    data: {},
  });
});

// A reader keeps its position and reads on from it.
let position = eventStreamStart(realmId);
const page = await events.readAfter(realmId, position, 100);
position = page.next;
```

**The read rule.** Every read takes a realm id; there is no read across realms,
and a read that leaves it out does not compile. `seq` alone cannot order a
reader: two transactions can commit in the opposite order of their `seq`
values, and a reader that had passed the later one would skip the earlier.
`readAfter` returns only rows whose `xid` is below the snapshot's xmin
(`pg_snapshot_xmin(pg_current_snapshot())`). Every transaction below it has
ended, so no row can still appear before the last one returned, and reading on
from `next` never skips or repeats an event. After a page shorter than the
limit, `next` is that horizon, so a filtered reader does not scan the same old
rows again.

**The lag.** The price of that rule is lag: a transaction left open holds back
every event written after it began, until it ends. That holds for any
transaction that has written something, on any database of the same Postgres
server. `oldestUnreadEventAge()` measures the wait, and the auth server
publishes it on `/metrics` as `qauth_events_oldest_unread_age_seconds`. Keep
transactions short, and never hold one open across a network call.

Migration 0029 is expand-only: one `CREATE TABLE` and its `CREATE INDEX`
statements. Migration 0032 adds the hash chain of admin events and the trigger
that refuses updates (below). Migration 0033 adds the two functions a writer
reads through and the trigger that keeps each row's `xid` its transaction's.

**No updates.** A trigger refuses every `UPDATE` on `events`, for every role
whose statements fire it, the owner included, even one that matches no row.
Only the retention job deletes (#536). A writing role is granted `INSERT` on
`events` and `EXECUTE` on `events_admin_chain_head` and `events_own_row`, and no
`SELECT` (#827): with it, a writer could read every realm's events, request IPs,
user agents and admin diffs included. `eventsWriterGrantStatements(role)`
returns the statements, which the per-role grants script (#498) will apply. That script is not built yet. QAuth creates no database users;
until the roles are split, the one database user owns the table, and the hash
chain shows an admin event it removed.

#### Admin events and the hash chain

Every admin change becomes an admin event (ADR-020 §3, ADR-019 Decision 7,
#459), written with `emitAdminEvent` in the transaction of the change. Admin
events are always on: no environment key and no realm setting turns them off.
Tests refuse by default: a configuration key, a realm column or a member a realm
`jsonb` column's type declares whose name holds an event word (`event`, `audit`,
`log`, `sink`, …) fails them unless an allow list gives the reason it turns
nothing off. The event's `data.diff` lists the changed fields with every secret
masked as `***`, and `data.approvals` both approvals of a two-admin operation.

```typescript
await db.transaction(async (tx) => {
  const before = await realmsRepo.findByIdOrThrow(realmId, tx);
  const after = await realmsRepo.update(realmId, change, tx);
  await events.emitAdminEvent(tx, {
    realm: realmId,
    actor: { type: 'user', id: adminId },
    operation: 'realms.policies.write',
    target: { type: 'realm', id: realmId },
    before: toJson(before),
    after: toJson(after),
    approvals,
  });
});
```

`before` and `after` must be plain JSON: convert a `Date` or a `Buffer` first.

A realm's admin events form one hash chain. Each admin row stores the `hash`
of the realm's admin row before it as `prev_hash` (32 zero bytes for the
first), and its own `hash` is SHA-256 over the chain format's id,
`qauth-event-chain/1-rc.0`, and a NUL byte, `prev_hash`, the row's `xid` as 8
bytes (unsigned, big-endian) and the RFC 8785 canonical JSON of its envelope
(`eventChainHash`). The format id is a release candidate until 1.0.0
(ADR-018 §5): a change to what the hash covers raises it. A changed row no longer hashes to its `hash`; a removed row
leaves the next row's `prev_hash` pointing at nothing. `xid` is not in the
envelope, but readers take rows in `(xid, seq)` order, so a row whose `xid` was
moved below a reader's position would be hidden from that reader: hashing it
makes that row break the chain (#827). The writer reads its transaction's id
(`pg_current_xact_id()`) before the insert, which leaves the column to its
default.

- **One chain per realm.** The writer holds the realm's advisory transaction
  lock from reading the chain head to the end of its transaction, so the chain
  runs in `seq` order. A unique index on `(realm_id, prev_hash)` lets no two
  rows follow one hash: a REPEATABLE READ or SERIALIZABLE writer that read a
  stale head gets a unique violation (23505) or a serialization failure
  (40001) instead of forking the chain; retry it. `emitInOwnTransaction` runs
  an admin event under READ COMMITTED.
- **Only at the head.** The trigger `events_admin_follows_head` refuses an
  admin row whose `prev_hash` is not the realm's head, or whose `seq` was not
  the identity's, so a role that can insert cannot make a row the head of a
  realm forever.
- **Its own transaction's `xid`.** The trigger `events_xid_from_transaction`
  refuses any row, admin or user, whose `xid` is not the inserting
  transaction's (#827), so a role that can insert cannot put a row behind a
  reader's position.
- **Emit last.** Because the lock lasts to the end of the transaction, write the
  admin event last. A transaction that writes admin events to several realms
  writes them in a fixed order, by realm id, or two such transactions can
  deadlock.
- **Checked on write.** The writer reads its row back, in a savepoint, and
  throws if the row does not hash as written; the savepoint undoes the insert,
  so a row the chain would reject never commits, even when the caller catches
  the error. The writer reads through two `SECURITY DEFINER` functions, not
  the table: `events_admin_chain_head(realm_id)` returns the realm's head
  hash, and `events_own_row(id)` returns the row only to the transaction that
  wrote it. A third, `events_oldest_unread_time()`, gives the auth server, a
  writer, the store's lag for `/metrics`. `verifyChain` and
  `events:verify-chain` read the table: run them as a role that may, such as
  the table owner, not as a writer.
- **What the chain shows.** The hash is unkeyed: whoever can rewrite a row and
  every row after it, or cut the newest rows, leaves a chain that verifies.
  Keep the head `verifyChain` returns outside the database, and verify from it
  later: `verifyChain(realmId, head)` first checks that the head's own row is
  still there with its hash (`anchor_missing`, `anchor_mismatch`), so a chain
  cut back to before it, or rewritten up to it, fails. It reads no row before
  the head: a single row changed there shows only in a run from the start, so
  run both. Rows after the kept head rewritten to the end, or cut, leave no
  break; keep each new head.
- **The `xid` is in the hash.** A full `pg_dump` and restore keeps each row's
  `xid` as data and loads the rows before it creates the triggers, so the
  chain still verifies. A `pg_restore --data-only` into a migrated schema is
  refused row by row by `events_xid_from_transaction`; it needs
  `--disable-triggers`, as the table owner. Rows chained by a build of `main`
  between #825 and #827 hashed without the `xid` and fail verification at the
  first of them; that database is for development, so reset it.
- **Grants.** Run `eventsWriterGrantStatements(role)` again for a role that
  got the writer grants from an earlier build: the statements revoke what the
  role held and grant `INSERT` and `EXECUTE` on the three functions.

#### Event delivery

The delivery role (`@qauth-labs/server-event-delivery`, #460) hands each event
to each destination of a route, at least once and with the same id, through
`createEventDeliveriesRepository`:

- **Fan-out.** Each realm with a destination of a route kind has a position
  for that kind in `event_delivery_positions`. `fanOut` reads the realm's
  events after it, below the horizon (the read rule of the
  [event store](#event-store)), and writes one row per destination of the kind
  whose type and category filters match, in the transaction that moves the
  position. A crash before the commit writes and moves nothing; a second run
  writes no row twice (`event_deliveries_event_destination_unique`). It takes a
  `pg_try_advisory_xact_lock` per realm and kind and leaves a stream another
  node holds. A stream seen for the first time starts at the horizon, and the
  position of a realm whose last destination of a kind went is removed: a new
  destination receives events from about the time it was added, not the
  realm's history. A node moves and removes only the positions of the kinds it
  serves, so nodes with different routes, as during a rollout, do not move
  each other's.
- **Claims and leases.** `claim` takes due rows of the destinations it is
  given with `FOR UPDATE SKIP LOCKED`, counts the attempt and leases each row:
  `locked_until` and `next_attempt_at` become the lease's end, so a worker that
  dies leaves rows that come due again. `record` writes an outcome only while
  the claim still holds the row (same attempt, lease not given back), so a
  worker whose lease ran out cannot overwrite a newer attempt. A due row whose
  attempts are used up was interrupted on its last one and ends `failed`
  (`attempt_interrupted`). A row whose event is stored in a later layout than
  this release reads is left to a node that reads it. A `hold` outcome, for a
  destination that holds its events for now, gives back the attempt the claim
  counted and keeps the last failure, so holds never use up the attempts.
- **Clock.** Every time in the queue is epoch milliseconds from the worker's
  clock, not the database's: the lease and the retry schedule run on one clock,
  and a test can drive them.
- **Retention.** `minOffered(realmId)` is the lowest position every
  destination has finished: before the realm's oldest unfinished row, and at
  most the lowest of its positions. A row is deleted with its event (`ON DELETE CASCADE`).
- **Subjects.** A destination may list `subjects`: it then gets only events
  whose `subject` (type and id) is one of them; an empty list matches none.
- **Grants.** `eventDeliveryGrantStatements(role)`: `SELECT` on `events`,
  `SELECT`, `INSERT` and `UPDATE` on `event_deliveries`, every row privilege
  on `event_delivery_positions`, `SELECT` on `ssf_streams`, and `SELECT` on
  `ssf_stream_subjects (stream_id, event_subject_type, event_subject_id)`,
  `realms (id, ssf_transmitter_enabled, issuer)` and
  `oauth_clients (id, enabled, suspended, scopes)`. Nothing else: not the raw
  subject a receiver sent, which may be an email address.

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
nx run infra-db:db:generate

# Run pending migrations
nx run infra-db:db:migrate

# Push schema changes directly (dev only)
nx run infra-db:db:push
```

In a deployment, migrations are applied by the migration runner
(`apps/migration-runner`, issue #474), not by drizzle-kit: one bundled Node
program that takes a Postgres advisory lock (`qauth:migrations`), applies the
pending migrations in one transaction with drizzle's `migrate()` and logs each
with its duration; `--check` lists the pending ones and changes nothing. Its
work, and the auth server's boot check, live in `src/lib/migrations/`, which
the package also exports as `@qauth-labs/infra-db/migrations`, an entry point
that loads only `pg` and `drizzle-orm`:

- `runMigrations({ connectionString, migrationsFolder, log })` and
  `checkMigrations(...)`, what the runner and its `--check` run.
- `readMigrationStatus(db, entries)`: the pending migrations by drizzle's own
  rule (newer than the newest applied `created_at`), and how many applied ones
  the list does not know (a database ahead of the code).
- `waitForMigrations(db, entries, { waitMs })`: waits while the database is
  behind, then throws `MigrationsPendingError` naming the missing migrations.
- `MIGRATION_LOCK_NAME`, `acquireMigrationLock` and `releaseMigrationLock`,
  for any step that must not run beside a migration.

```bash
# Build and run the runner against DATABASE_URL, or only check
pnpm nx run migration-runner:migrate
pnpm nx run migration-runner:migrate -- --check
```

### Database Management

```bash
# Open Drizzle Studio for database management
nx run infra-db:db:studio

# Drop all tables (DANGER: use with caution)
nx run infra-db:db:drop
```

### Seeding

Two seeders live under `src/scripts/`. Both require `DATABASE_URL` in the environment (or in the repo-root `.env` — `dotenv` is loaded automatically).

```bash
# Dev fixture generator (destructive — calls reset() then replants realms + oauth_clients)
nx run infra-db:db:seed

# Idempotent OAuth-client provisioner (additive; production-safe)
# Reads a JSON manifest; generates 32-byte client secrets; argon2id-hashes
# them; prints plaintext secrets once to STDOUT (the DB only keeps hashes).
# Existing client_ids are skipped unless `--rotate` is passed.
nx run infra-db:db:seed-oauth-clients -- --manifest=/path/to/manifest.json [--rotate]

# Operator-only suspension of one client (or --lift to end it)
nx run infra-db:db:suspend-oauth-client -- --realm=<realm name> --client-id=<client_id> [--lift]
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

`webauthn_allowed_origins` lists the extra origins a native app's passkey ceremonies may come from (#467), in the form a browser writes in `clientDataJSON.origin`: an Android app's `android:apk-key-hash:<base64url SHA-256 of its signing certificate>`, or an `https` origin under the RP ID. The manifest is the only way to set `oauth_clients.webauthn_allowed_origins`: no route writes it, so a client cannot widen where its passkeys are accepted.

`dpop_bound_access_tokens: true` marks a client that always uses DPoP at the token endpoint (RFC 9449 §5.2, #480): while `DPOP_ENABLED` is on, the auth server refuses its token requests that carry no `DPoP` proof, whatever the grant. The manifest is the only way to set `oauth_clients.dpop_bound_access_tokens`: dynamic registration, CIMD documents and `/api/clients` leave it `false`.

`verified_domain` is the domain the operator verified for the client (ADR-019 Decision 6, #593), such as `notes.example.com`. Consent and every other screen that names the client show it first, above the name the client declares, and highlight its registrable domain. It is stored lower case and in ASCII form (`bücher.example` becomes `xn--bcher-kva.example`); a URL, a port, an IP address or a single label is refused. It counts only while the client is operator-provisioned, so an owner who changes the redirect URIs also takes it off the screens. Without it the screens say the app is unverified and show the host that receives the code. Setting it is a security operation of the admin API (`clients.update`, `qauth:admin:security`); until that ships, the manifest is the only way to set `oauth_clients.verified_domain`: dynamic registration, CIMD documents and `/api/clients` leave it empty, and a CIMD entry may not carry it, because a CIMD client's verified domain is the host of its client id. The seeder writes an existing client only with `--rotate`, which also issues it a new secret; to set the domain of an existing client without rotating, `UPDATE oauth_clients SET verified_domain = '<domain>' WHERE realm_id = '<realm id>' AND client_id = '<client_id>' AND provisioned_by_operator`; the screens read the column only while `provisioned_by_operator` is true, so the statement changes nothing on a client that is not operator-provisioned (it reports `UPDATE 0`). The database refuses a value that is not in the stored form (lower case, `xn--` labels, two or more labels, no port).

Both seeders mark their clients `provisioned_by_operator = true`, and so does the system client the auth-server creates for its own login. Only such a client receives authorization error responses by automatic redirect (RFC 9700 §4.11.2); every client created through `POST /oauth/register`, a CIMD document or `POST /api/clients` gets them on an issuer page. A `--rotate` run sets the marker on the clients it rewrites, which is how an operator marks a client that migration 0023's backfill left unmarked.

`oauth_clients.enabled` is the client owner's switch: `PATCH /api/clients/:id` may set it either way. An operator who must keep a client off **suspends** it instead (`oauth_clients.suspended`, `suspended_at`). A suspended client is refused wherever a disabled one is, no route writes the column, and a CIMD re-resolution never touches it. `db:suspend-oauth-client` sets or lifts it in one transaction with a `client.suspended` / `client.suspension_lifted` event (actor `operator_cli`, the operating-system user when there is one); the equivalent by hand is `UPDATE oauth_clients SET suspended = true, suspended_at = <epoch ms> WHERE client_id = '<client_id>'`. Lifting a suspension leaves `enabled` as it is. Migration 0023 suspends every client that was disabled when it ran, since the row does not record whether the operator or the owner disabled it.

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
│   │   │   ├── sessions.repository.ts    # sessions (realm-bound lookups)
│   │   │   └── integration-setup.ts
│   │   ├── schema/
│   │   │   ├── index.ts        # Main schema exports
│   │   │   ├── core.ts         # Core tables: realms, users, oauth_clients, api_keys
│   │   │   ├── tokens.ts       # email_verification_tokens, authorization_codes, refresh_tokens
│   │   │   ├── consents.ts     # oauth_consents
│   │   │   ├── sessions.ts     # sessions, session_clients (ADR-019 Decision 3)
│   │   │   ├── audit.ts        # audit_logs (read-only since #458)
│   │   │   ├── admin-audit.ts  # admin_audit_log, admin_audit_log_checkpoints (ADR-019 Decision 7)
│   │   │   ├── roles.ts        # roles, user_roles (currently unused)
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
- **authorization_codes**: OAuth authorization codes with PKCE challenges, plus `auth_time` (0013) and `assurance_level` (0016, ADR-010); `session_id` (0042, #549) names the browser session behind the code, the ID token's `sid`, and a deleted session sets it to NULL
- **refresh_tokens**: Refresh tokens with rotation support

### Federation Tables

- **oid4vp_request_states**: OID4VP request/response correlation — realm-scoped, unique `state_hash`, a DCQL query, expiry and single-use `redeemed_at`. Unused unless `WALLET_FEDERATION_ENABLED` is on

### Key Tables (ADR-019 Decision 9)

- **realm_keys**: Each realm's keys, one row per key, per purpose and (for webhook and upstream client-assertion keys) per `scope_id`. The material is stored envelope-encrypted (`ciphertext`, `iv`, `wrapped_dek`, with `kek_ref` naming the KEK and `aad_version` the associated-data layout). `status` is `next`, `active`, `retired` or `compromised`; a partial unique index allows one `active` key per realm, purpose, scope and algorithm, and `kid` is unique per realm. Only the signer's database user may read it once the per-role grants (#498) are applied
- **realm_public_keys**: The public JWK of every published key, keyed by `(realm_id, kid)`. Its foreign key to the `realm_keys` row covers `purpose`, `algorithm` and `status` with `ON UPDATE CASCADE`, so a status change on the key row (a compromise included) reaches the public row in the same statement; change the status on `realm_keys` only. Every role may read it for the JWKS and for verification. Symmetric purposes have no row here: CHECKs require a `kty` other than `oct` and refuse private JWK members

### Event Store (ADR-019 Decision 8)

- **events**: One row per event, written in the transaction of the change it records: the envelope's `id` (a UUIDv7, unique), realm, category, type, time, actor, subject, client, request and `data`, plus `seq` (an identity), `xid` (the writing transaction, `xid8`) and `schema_version` (the row layout, 1). Readers take a realm's rows in `(xid, seq)` order below their snapshot's xmin (`idx_events_realm_position`). Also indexed by `(realm_id, type)`, by `subject_id` and by `(realm_id, category, time)` for retention (#536). No foreign keys: an event outlives the realm, user or client it names
- **event_chain_anchors**: Per realm, the `seq` and `hash` of the last admin row the retention job deleted: the oldest admin row left carries that hash as its `prev_hash`, and `verifyChain` starts there. Written by the job in the transaction that deletes the rows, and only moved forward (#536)

- **event_deliveries**: One row per destination (`destination_kind`, `destination_id`) and event (`event_id`, `ON DELETE CASCADE`), unique on that triple: status (`pending`, `delivered`, `failed`), attempt count, `next_attempt_at`, `locked_until` (the lease), last status code and error class, and the event's realm, position (`event_xid`, `event_seq`) and time. Partial indexes on pending rows serve the claims, `minOffered` and the lag (#460)
- **event_delivery_positions**: The fan-out's position in each realm's stream, per route kind that has a destination there; keyed by `(realm_id, destination_kind)` (#460)

### Admin Audit Tables (ADR-019 Decision 7)

- **admin_audit_log**: One row per admin operation, written in the transaction of the change. Keyed by `(realm_id, seq)`: one hash chain per target realm, `seq` from 1 without a gap, each row carrying the previous row's hash (`prev_hash`) and its own (`row_hash`). It records the actor kind (`human_admin`, `service_account`, `break_glass_operator`, `host_operator`), the actor and the actor's realm, the full act chain when the actor acted for a user, the operation id and class, its effects and outcome, the diff with secrets masked, the approvals, the request digest, the trace id and the time. No foreign keys: a realm's record outlives the realm row. Append-only by trigger; a writing role is granted `INSERT` and `SELECT` only
- **admin_audit_log_checkpoints**: The `seq` and `row_hash` of the last row each prune removed, so the oldest retained row still verifies. Written by `admin_audit_log_prune()`; a trigger accepts a checkpoint only over an unbroken run of rows at least 90 days old. Append-only too
- **admin_roles**: A realm's custom admin roles (migration 0043, ADR-019 Decision 7, #510): a name unique in the realm, never a built-in role's, and permission ids from the auth server's catalog; disabled, never deleted while a grant names it. Read by realm id first (#489)
- **admin_grants**: Which account administers which realm through which role (migration 0043, #510): a built-in role by name or a custom role by id, one target realm or every realm (NULL), the creator, and the creation, revocation and last security-change times in epoch ms. The triggers `admin_grants_realm_rule` (only an operator-realm account holds a grant on every realm or another realm; a custom role only within its realm), `admin_grants_insert_live` (written live, at the database's time) and `admin_grants_revoke_only` (revoked, never changed) hold for every writer. Read by realm id first: the realm a grant covers, or its account's realm; revoked only from its account's realm (#489)

### Additional Tables

- **sessions**: Browser sessions (ADR-019 Decision 3, #468): one row per account signed in on one browser, in one realm. The `id` (`uuidv7()`) is the session's `sid`. Holds the authentication (`auth_time`, `amr`, `assurance_level`), the address and user agent at creation, `last_seen_at`, the absolute end `expires_at`, and `revoked_at` with `revoked_reason` (set together). `(user_id, realm_id)` references `users (id, realm_id)`, so a session never names a user of another realm. Not stored here: the cookie, the CSRF values and the consent scopes. The auth server writes it through the session service (#469) at every browser sign-in and reads it whenever it resolves the session cookie (#488)
- **session_clients**: The clients a session has served, keyed by `(session_id, oauth_client_id)`, for back-channel logout. Written in the transaction that mints an authorization code, under a share lock on the live session (`recordClient`, #549); read by session, by user or by client within a realm, for live sessions only. Revoking the session deletes its rows and returns them; deleting the session or the client deletes them too
- **audit_logs**: The audit log of the releases before the event store; read-only since #458, its rows copied into `events`
- **api_keys**: Environment-gated static developer API keys (ADR-008 §6)
- **roles**: Role-based access control (currently unused)
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
3. Generate migrations using `nx run infra-db:db:generate`
4. Review the generated migration file in `drizzle/` directory
5. Run migrations using `nx run infra-db:db:migrate`

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
