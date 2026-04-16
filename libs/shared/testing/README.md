# Testing Library

Test helpers and utilities for QAuth. This library provides Fastify test helpers, Supertest utilities, and test fixtures to simplify testing across the QAuth monorepo.

## Overview

The `@qauth-labs/shared-testing` library provides:

- **Fastify Test Helpers**: Utilities for building and managing test Fastify instances
- **Supertest Helpers**: Utilities for making HTTP requests in tests
- **Test Fixtures**: Reusable test data factories for users, realms, and other entities
- **Type-Safe API**: Full TypeScript support

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import {
  buildTestApp,
  closeTestApp,
  createTestRequest,
  createUserFixture,
  createRealmFixture,
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

#### User Fixtures

Create user test data with `createUserFixture` and `createUserFixtures`.

```typescript
import { createUserFixture, createUserFixtures } from '@qauth-labs/shared-testing';

// Create a single user fixture
const user = createUserFixture({
  email: 'user@example.com',
  emailVerified: true,
});

// Create multiple user fixtures
const users = createUserFixtures(5);
```

**`createUserFixture(overrides?)`**

Creates a single user fixture with optional overrides.

**Parameters:**

- `overrides?: Partial<UserFixture>` - Optional overrides for default values

**Returns:** User fixture object

**Example:**

```typescript
const user = createUserFixture({
  email: 'custom@example.com',
  emailVerified: true,
});
```

**`createUserFixtures(count)`**

Creates multiple user fixtures.

**Parameters:**

- `count: number` - Number of user fixtures to create

**Returns:** Array of user fixture objects

**Example:**

```typescript
const users = createUserFixtures(10);
expect(users).toHaveLength(10);
```

#### Realm Fixtures

Create realm test data with `createRealmFixture`.

```typescript
import { createRealmFixture } from '@qauth-labs/shared-testing';

// Create a realm fixture
const realm = createRealmFixture({
  name: 'my-realm',
});
```

**`createRealmFixture(overrides?)`**

Creates a single realm fixture with optional overrides.

**Parameters:**

- `overrides?: Partial<RealmFixture>` - Optional overrides for default values

**Returns:** Realm fixture object

**Example:**

```typescript
const realm = createRealmFixture({
  name: 'test-realm',
});
```

## Complete Example

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildTestApp, closeTestApp, createTestRequest } from '@qauth-labs/shared-testing';
import { createUserFixture, createRealmFixture } from '@qauth-labs/shared-testing';
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
    const userData = createUserFixture({
      email: 'test@example.com',
      emailVerified: true,
    });

    const response = await request.post('/users').send(userData);

    expect(response.status).toBe(201);
    expect(response.body.user.email).toBe('test@example.com');
  });

  it('should get a user by ID', async () => {
    const userData = createUserFixture();
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

    const users = createUserFixtures(5).map((user) => ({
      ...user,
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

#### `createUserFixture(overrides?): UserFixture`

Creates a single user fixture with optional overrides.

#### `createUserFixtures(count): UserFixture[]`

Creates multiple user fixtures.

#### `createRealmFixture(overrides?): RealmFixture`

Creates a single realm fixture with optional overrides.

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

## License

Apache-2.0
