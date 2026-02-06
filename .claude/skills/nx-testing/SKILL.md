---
name: nx-testing
description: Testing workflows with Vitest in Nx monorepo. Use when writing tests, running test suites, or debugging test failures.
---

# Nx Testing Workflows

## Test Stack

- **Runner**: Vitest 4.x
- **HTTP Testing**: Supertest
- **Containers**: Testcontainers
- **Coverage**: Built-in Vitest

## Running Tests

```bash
# Single project
pnpm nx test auth-server
pnpm nx test auth-server --watch
pnpm nx test auth-server --coverage

# Multiple projects
pnpm nx run-many -t test --all
pnpm nx affected -t test
pnpm nx run-many -t test --all --parallel=3

# Vitest UI
pnpm test:ui
```

## Test File Patterns

Co-locate tests with source:

```
libs/server/jwt/src/
├── jwt.service.ts
├── jwt.service.spec.ts
└── index.ts
```

## Unit Test Example

```typescript
import { describe, it, expect, beforeEach } from 'vitest';
import { createService } from './service';

describe('Service', () => {
  let service: ReturnType<typeof createService>;

  beforeEach(() => {
    service = createService();
  });

  it('should do something', () => {
    expect(service.method()).toBe(expected);
  });
});
```

## Integration Test with Fastify

```typescript
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { buildTestApp } from '@qauth/shared-testing';
import type { FastifyInstance } from 'fastify';

describe('Route', () => {
  let app: FastifyInstance;

  beforeAll(async () => {
    app = await buildTestApp();
  });

  afterAll(async () => {
    await app.close();
  });

  it('should return 200', async () => {
    const response = await app.inject({
      method: 'GET',
      url: '/health',
    });
    expect(response.statusCode).toBe(200);
  });
});
```

## Best Practices

1. Test business logic in isolation
2. Use `@qauth/shared-testing` utilities
3. Use Testcontainers for real PostgreSQL
4. Mock external services
5. Name tests descriptively
