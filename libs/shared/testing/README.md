# Testing Library

Test helpers and utilities for QAuth. This library provides Fastify test helpers, Supertest utilities, and test fixtures to simplify testing across the QAuth monorepo.

## Overview

The `@qauth-labs/shared-testing` library provides:

- **Fastify Test Helpers**: Utilities for building and managing test Fastify instances
- **Supertest Helpers**: Utilities for making HTTP requests in tests
- **Test Fixtures**: Reusable test data factories for users, realms, and other entities
- **Docker Integration Testing**: Postgres and Redis databases of each suite's own on shared testcontainers servers, for integration tests
- **Type-Safe API**: Full TypeScript support

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import {
  buildTestApp,
  closeTestApp,
  createTestRequest,
  createRealmFixture,
  startPostgresContainer,
  startRedisContainer,
  requireDockerOrSkip,
  POSTGRES_IMAGE,
} from '@qauth-labs/shared-testing';
```

## Usage

### Fastify Test Helpers

#### `buildTestApp(appPlugin, options?)`

Builds a test Fastify instance with the given plugin.

```typescript
import { buildTestApp } from '@qauth-labs/shared-testing';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';

// Build test app with database plugin
const app = await buildTestApp(databasePlugin, {
  logger: false, // Disable logger in tests (default: false)
});
```

**Parameters:**

- `appPlugin: FastifyPluginAsync` - Fastify plugin to register
- `options?: { logger?: boolean }` - Optional configuration
  - `logger?: boolean` - Enable/disable logger (default: `false`)

**Returns:** Promise resolving to configured Fastify instance

**Example:**

```typescript
import { buildTestApp } from '@qauth-labs/shared-testing';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';

const app = await buildTestApp(databasePlugin, { logger: false });
```

#### `closeTestApp(app)`

Closes a test Fastify instance and cleans up resources.

```typescript
import { buildTestApp, closeTestApp } from '@qauth-labs/shared-testing';

const app = await buildTestApp(databasePlugin);

// Use app in tests
// ...

// Clean up after tests
await closeTestApp(app);
```

**Parameters:**

- `app: FastifyInstance` - Fastify instance to close

**Returns:** Promise resolving when the app is closed

**Example:**

```typescript
import { buildTestApp, closeTestApp } from '@qauth-labs/shared-testing';

describe('Database Plugin', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildTestApp(databasePlugin);
  });

  afterAll(async () => {
    await closeTestApp(app);
  });

  it('should work', async () => {
    // Test code
  });
});
```

### Supertest Helpers

#### `createTestRequest(app)`

Creates a Supertest request instance from a Fastify app.

```typescript
import { buildTestApp, createTestRequest } from '@qauth-labs/shared-testing';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';

const app = await buildTestApp(databasePlugin);
const request = createTestRequest(app);

// Make HTTP requests
const response = await request.get('/health');
expect(response.status).toBe(200);
```

**Parameters:**

- `app: FastifyInstance` - Fastify instance to create request from

**Returns:** Supertest request instance

**Example:**

```typescript
import { buildTestApp, createTestRequest } from '@qauth-labs/shared-testing';

const app = await buildTestApp(databasePlugin);
const request = createTestRequest(app);

// GET request
const getResponse = await request.get('/users/123');

// POST request
const postResponse = await request.post('/users').send({
  email: 'user@example.com',
  password: 'password123',
});
```

### Test Fixtures

#### Realm Fixtures

Realms are the only entity with fixture helpers in this library.

```typescript
import { createRealmFixture, createRealmFixtures } from '@qauth-labs/shared-testing';

// A single realm fixture — name defaults to `test-realm-<timestamp>`
const realm = createRealmFixture({ name: 'my-realm' });

// Multiple, each with a distinct generated name
const realms = createRealmFixtures(5);
```

**`createRealmFixture(overrides?)`**

**Parameters:**

- `overrides?: Partial<RealmFixture>` — overrides for the defaults (`name`, `enabled`)

**Returns:** `RealmFixture`

**`createRealmFixtures(count)`**

**Parameters:**

- `count: number` — how many to create

**Returns:** `RealmFixture[]`

> **There are no user fixtures.** Earlier revisions of this README documented
> `createUserFixture` / `createUserFixtures`; no such exports have ever shipped.
> Build users inline instead — and note that since ADR-002 (#230) a user is an
> identity anchor with no `email` or `passwordHash`, so a fixture taking those
> fields would not match the schema either. See
> [`libs/infra/db/README.md`](../../infra/db/README.md) for the two-write
> registration shape.

### Docker Integration Testing

For repository and end-to-end suites that need a real Postgres or Redis, the
library hands each suite databases of its own on throwaway
[testcontainers](https://testcontainers.com/) servers: `postgres:18-alpine` and
`redis:7-alpine`, the images docker-compose runs (PostgreSQL 18 is required for
native `uuidv7()`).

#### How the servers are shared

`vitest.integration.config.mts` runs the integration files side by side, and its
global setup (`src/integration-global-setup.ts`) starts the servers once per
`vitest` run:

- **One Postgres server per worker slot** (`maxWorkers` of them), each with a
  template database that has every generated migration applied. A slot runs one
  file at a time, so the files on a server follow one another and never overlap.
  One server for the whole run would not do: a server's transaction horizon
  (`pg_snapshot_xmin(pg_current_snapshot())`) spans its databases, and the event
  store reads it to decide which events are final, so a write transaction open in
  one suite's database would hold back another suite's event delivery and
  retention.
- **One Redis server**, on which each suite gets a pair of logical databases no
  other suite of the run is given (`redis://…/<n>`).

The setup passes the servers to the workers through the environment
(`QAUTH_TEST_SHARED_POSTGRES_URLS`, `QAUTH_TEST_SHARED_POSTGRES_TEMPLATE`,
`QAUTH_TEST_SHARED_REDIS_URL`). Without a reachable Docker daemon it starts
nothing: the suites skip, or fail on CI, through `requireDockerOrSkip()` as
before. Without the setup (another config), every suite gets containers of its
own.

`QAUTH_INTEGRATION_WORKERS` sets how many files run at once (and so how many
Postgres servers start). The default is 3 on CI and half the cores, at most 4,
locally.

#### `startPostgresContainer(options?): Promise<StartedPostgres>`

A new database for the suite on its slot's shared server, or a container of its
own. Options:

- `schema: 'empty' | 'migrated'` — `'empty'` (the default) for a suite that
  applies migrations itself, all or some of them; `'migrated'` for a copy of the
  migrated template, which saves applying every migration again.
- `privateContainer: true` — a Postgres container of the suite's own. Use it for a
  suite that stops, kills, pauses or restarts the server, changes a server-wide
  setting, terminates backends it does not own, or creates a cluster-wide object
  (a role, a tablespace): on a shared server that would reach the suites that run
  on it after this one.

The returned `StartedPostgres` has:

- `connectionString: string` — node-postgres / Drizzle compatible URL of the suite's database
- `port: number` — the host port the server listens on
- `createDatabase(): Promise<string>` — a further empty database on the same
  server, uniquely named, for a suite that needs one per case
- `stop(): Promise<void>` — drop the suite's databases (shared server) or stop and
  remove the container (private)

A query that reads the server as a whole (`pg_locks`, `pg_stat_activity`) should
keep to the suite's database (`datname = current_database()`, or
`database = (SELECT oid FROM pg_database WHERE datname = current_database())`):
the server holds other suites' databases too, and copies of one template share
their tables' OIDs.

#### `startRedisContainer(options?): Promise<StartedRedis>`

A pair of logical databases for the suite on the run's shared Redis server, or,
with `privateContainer: true`, a container of its own. Use the private container
for a suite that stops or reconfigures the server, or relies on what spans
logical databases (pub/sub, keyspace notifications, `FLUSHALL`). Reset a suite's
keys with `FLUSHDB`, never `FLUSHALL`, which would empty every suite's.

The returned `StartedRedis` has `connectionUrl`, `spareConnectionUrl` (the second
logical database, for a node that must share no key with the others), `port` and
`stop()` (empty both databases, or stop the private container).

#### `requireDockerOrSkip(): Promise<boolean>`

The Docker gate every suite calls in its `beforeAll`: `true` when a daemon is
reachable; `false` locally when it is not, so the suite skips; and it throws on
CI, so a daemon-less runner cannot turn the suite into a green no-op.

#### `isDockerAvailable(): Promise<boolean>`

The raw probe behind `requireDockerOrSkip()`. Prefer the gate in suites.

#### `POSTGRES_IMAGE`

The pinned image string (`'postgres:18-alpine'`), exported so callers can assert
on or reuse it.

**Example:**

```typescript
import { describe, it, beforeAll, afterAll, expect } from 'vitest';
import {
  requireDockerOrSkip,
  startPostgresContainer,
  type StartedPostgres,
} from '@qauth-labs/shared-testing';

describe('OAuth clients repository (integration)', () => {
  let pg: StartedPostgres | undefined;
  let dockerUp = false;

  beforeAll(async () => {
    dockerUp = await requireDockerOrSkip();
    if (!dockerUp) return;
    pg = await startPostgresContainer({ schema: 'migrated' });
    // e.g. process.env.DATABASE_URL = pg.connectionString;
  }, 120_000); // pulling/booting the image can take a while on a cold cache

  afterAll(async () => {
    await pg?.stop();
  });

  it('persists a row', async (ctx) => {
    if (!dockerUp || !pg) return ctx.skip();
    // run repository code against pg.connectionString
    expect(pg.port).toBeGreaterThan(0);
  });
});
```

## Complete Example

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildTestApp, closeTestApp, createTestRequest } from '@qauth-labs/shared-testing';
import { createRealmFixture } from '@qauth-labs/shared-testing';
import { databasePlugin } from '@qauth-labs/fastify-plugin-db';

describe('User API', () => {
  let app: FastifyInstance;
  let request: ReturnType<typeof createTestRequest>;

  beforeAll(async () => {
    app = await buildTestApp(databasePlugin, { logger: false });
    request = createTestRequest(app);
  });

  afterAll(async () => {
    await closeTestApp(app);
  });

  it('should create a user', async () => {
    // No user fixture helper ships — build the payload inline.
    const userData = { realmId: createRealmFixture().name, email: 'test@example.com' };

    const response = await request.post('/users').send(userData);

    expect(response.status).toBe(201);
    expect(response.body.user.email).toBe('test@example.com');
  });

  it('should get a user by ID', async () => {
    const userData = { email: 'lookup@example.com' };
    const createResponse = await request.post('/users').send(userData);
    const userId = createResponse.body.user.id;

    const getResponse = await request.get(`/users/${userId}`);

    expect(getResponse.status).toBe(200);
    expect(getResponse.body.user.id).toBe(userId);
  });

  it('should create users in a realm', async () => {
    const realm = createRealmFixture({ name: 'test-realm' });
    const realmResponse = await request.post('/realms').send(realm);
    const realmId = realmResponse.body.realm.id;

    const users = Array.from({ length: 5 }, (_, i) => ({
      email: `user-${i}@example.com`,
      realmId,
    }));

    for (const userData of users) {
      const response = await request.post('/users').send(userData);
      expect(response.status).toBe(201);
    }
  });
});
```

## API

### Fastify Test Helpers

#### `buildTestApp(appPlugin, options?): Promise<FastifyInstance>`

Builds a test Fastify instance with the given plugin.

#### `closeTestApp(app): Promise<void>`

Closes a test Fastify instance and cleans up resources.

### Supertest Helpers

#### `createTestRequest(app): ReturnType<typeof request>`

Creates a Supertest request instance from a Fastify app.

### Test Fixtures

#### `createRealmFixture(overrides?): RealmFixture`

Creates a single realm fixture with optional overrides.

#### `createRealmFixtures(count): RealmFixture[]`

Creates multiple realm fixtures, each with a distinct generated name.

> There are no `createUserFixture` / `createUserFixtures` exports — see
> [Realm Fixtures](#realm-fixtures) above.

### Docker Integration Testing

#### `startPostgresContainer(options?): Promise<StartedPostgres>`

A database of the suite's own on its worker slot's shared Postgres server (empty,
or a copy of the migrated template with `schema: 'migrated'`), or a private
container with `privateContainer: true`. Returns
`{ connectionString, port, createDatabase(), stop() }`.

#### `startRedisContainer(options?): Promise<StartedRedis>`

A pair of logical databases of the suite's own on the run's shared Redis server,
or a private container with `privateContainer: true`. Returns
`{ connectionUrl, spareConnectionUrl, port, stop() }`.

#### `requireDockerOrSkip(): Promise<boolean>`

`true` when a Docker daemon is reachable; `false` locally when not (skip the
suite); throws on CI.

#### `isDockerAvailable(): Promise<boolean>`

Resolves `true` when a Docker daemon is reachable, `false` otherwise.

#### `POSTGRES_IMAGE: string`

The pinned Postgres image (`'postgres:18-alpine'`).

## Development

### Running Tests

```bash
pnpm nx test shared-testing
```

### Type Checking

```bash
pnpm nx typecheck shared-testing
```

## Related Libraries

This library is used by test suites across the QAuth monorepo. It provides common testing utilities for:

- [`@qauth-labs/fastify-plugin-db`](../../fastify/plugins/db/README.md): Database plugin tests
- [`@qauth-labs/fastify-plugin-cache`](../../fastify/plugins/cache/README.md): Cache plugin tests
- [`@qauth-labs/fastify-plugin-password`](../../fastify/plugins/password/README.md): Password plugin tests
- [`@qauth-labs/fastify-plugin-email`](../../fastify/plugins/email/README.md): Email plugin tests

## Dependencies

- `fastify`: Fast HTTP server framework
- `supertest`: HTTP assertion library
- `vitest`: Test runner
- `testcontainers`: Disposable Docker containers for integration tests (Postgres and Redis)
- `ioredis`: Hands each suite its logical Redis databases on the shared server, and empties them

## License

Apache-2.0
