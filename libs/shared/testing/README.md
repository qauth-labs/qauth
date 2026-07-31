# Testing Library

Test helpers and utilities for QAuth. This library provides Fastify test helpers, Supertest utilities, and test fixtures to simplify testing across the QAuth monorepo.

## Overview

The `@qauth-labs/shared-testing` library provides:

- **Fastify Test Helpers**: Utilities for building and managing test Fastify instances
- **Supertest Helpers**: Utilities for making HTTP requests in tests
- **Test Fixtures**: Reusable test data factories for users, realms, and other entities
- **Docker Integration Testing**: A disposable PostgreSQL testcontainer for repository integration tests
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
  isDockerAvailable,
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

For repository/integration suites that need a real database, the library exposes
a disposable PostgreSQL [testcontainer](https://testcontainers.com/). It starts a
throwaway `postgres:18-alpine` container (the same image as docker-compose;
PostgreSQL 18 is required for native `uuidv7()`), waits until Postgres is genuinely
ready, and hands you a connection string to run migrations and tests against.

#### `startPostgresContainer(): Promise<StartedPostgres>`

Starts a disposable PostgreSQL 18 container and resolves once it is accepting
connections. Requires a running Docker daemon. The returned `StartedPostgres` has:

- `connectionString: string` — node-postgres / Drizzle compatible URL
- `port: number` — the host port mapped to the container's `5432`
- `stop(): Promise<void>` — stop and remove the container

#### `isDockerAvailable(): Promise<boolean>`

Best-effort probe for a reachable Docker daemon. Call it first so suites can
`describe.skip` (instead of failing) on CI lanes or sandboxes where Docker is
absent.

#### `POSTGRES_IMAGE`

The pinned image string (`'postgres:18-alpine'`), exported so callers can assert
on or reuse it.

**Example:**

```typescript
import { describe, it, beforeAll, afterAll, expect } from 'vitest';
import {
  startPostgresContainer,
  isDockerAvailable,
  type StartedPostgres,
} from '@qauth-labs/shared-testing';

const dockerAvailable = await isDockerAvailable();

describe.skipIf(!dockerAvailable)('OAuth clients repository (integration)', () => {
  let pg: StartedPostgres;

  beforeAll(async () => {
    pg = await startPostgresContainer();
    // Connect with pg/Drizzle and apply migrations against pg.connectionString…
    // e.g. process.env.DATABASE_URL = pg.connectionString;
  }, 120_000); // pulling/booting the image can take a while on a cold cache

  afterAll(async () => {
    await pg.stop();
  });

  it('persists a row', async () => {
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

#### `startPostgresContainer(): Promise<StartedPostgres>`

Starts a disposable `postgres:18-alpine` container for integration tests and
resolves once it is ready. Returns `{ connectionString, port, stop() }`.

#### `isDockerAvailable(): Promise<boolean>`

Resolves `true` when a Docker daemon is reachable, `false` otherwise (use to skip
integration suites gracefully).

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
- `testcontainers`: Disposable Docker containers for integration tests (Postgres harness)

## License

Apache-2.0
