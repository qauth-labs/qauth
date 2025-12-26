# QAuth Errors Library

Centralized error classes and error handling utilities for the QAuth platform. This library provides domain-specific error types organized by their use case.

## Overview

The `@qauth/errors` library provides a comprehensive set of error classes and utilities for consistent error handling across the QAuth platform. Errors are organized by domain (common, database, etc.) to maintain clear separation of concerns.

## Features

- **Domain-Organized Errors**: Errors grouped by domain (common, database, etc.)
- **Type-Safe Error Classes**: Custom error classes with proper TypeScript typing
- **Database Error Helpers**: Utilities for identifying and handling database-specific errors
- **Consistent Error Handling**: Standardized error messages and error structure across the platform

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { NotFoundError, UniqueConstraintError } from '@qauth/errors';
```

## Usage

### Common Errors

Common errors are domain-agnostic and can be used across different parts of the application.

#### NotFoundError

Thrown when an entity is not found in the database or any data store.

```typescript
import { NotFoundError } from '@qauth/errors';

// In a repository or service
async function getUser(id: string) {
  const user = await db.query.users.findFirst({ where: eq(users.id, id) });
  if (!user) {
    throw new NotFoundError('User', id);
  }
  return user;
}

// Error message: "User with id abc123 not found"
```

### Database Errors

Database-specific errors and utilities for handling database operations.

#### UniqueConstraintError

Thrown when a unique constraint is violated in the database.

```typescript
import {
  UniqueConstraintError,
  isUniqueConstraintError,
  extractConstraintName,
} from '@qauth/errors';

try {
  await db.insert(users).values({ email: 'existing@example.com' });
} catch (error) {
  if (isUniqueConstraintError(error)) {
    const constraint = extractConstraintName(error) || 'users_email_unique';
    throw new UniqueConstraintError(constraint, error);
  }
  throw error;
}
```

#### Database Error Helpers

Utilities for identifying and extracting information from database errors.

```typescript
import { isUniqueConstraintError, extractConstraintName } from '@qauth/errors';

try {
  // Database operation
  await db.insert(users).values(userData);
} catch (error) {
  // Check if it's a unique constraint violation
  if (isUniqueConstraintError(error)) {
    // Extract the constraint name
    const constraint = extractConstraintName(error);
    console.log(`Constraint violated: ${constraint}`);

    // Handle appropriately
    throw new UniqueConstraintError(constraint || 'unknown', error);
  }

  // Re-throw other errors
  throw error;
}
```

## Error Classes

### NotFoundError

**Location**: `@qauth/errors` (from `common` domain)

**Constructor**:

```typescript
new NotFoundError(entity: string, id: string)
```

**Properties**:

- `name`: `'NotFoundError'`
- `message`: `"{entity} with id {id} not found"`
- `statusCode`: `404` (HTTP status code for REST API responses)

**Example**:

```typescript
throw new NotFoundError('User', 'user-123');
// Error message: "User with id user-123 not found"
// statusCode: 404
```

### UniqueConstraintError

**Location**: `@qauth/errors` (from `database` domain)

**Constructor**:

```typescript
new UniqueConstraintError(constraint: string, cause?: unknown)
```

**Properties**:

- `name`: `'UniqueConstraintError'`
- `message`: `"Unique constraint violated: {constraint}"`
- `statusCode`: `409` (HTTP status code for REST API responses)
- `constraint`: The name of the violated constraint
- `cause`: The original error that caused this error (if provided)

**Example**:

```typescript
throw new UniqueConstraintError('users_email_unique', originalError);
// Error message: "Unique constraint violated: users_email_unique"
// statusCode: 409
```

## Helper Functions

### isUniqueConstraintError

Checks if an error is a PostgreSQL unique constraint violation.

```typescript
function isUniqueConstraintError(error: unknown): boolean;
```

**Returns**: `true` if the error is a PostgreSQL unique constraint violation (error code `23505`), `false` otherwise.

**Example**:

```typescript
try {
  await db.insert(users).values(userData);
} catch (error) {
  if (isUniqueConstraintError(error)) {
    // Handle unique constraint violation
  }
}
```

### extractConstraintName

Extracts the constraint name from a PostgreSQL error.

```typescript
function extractConstraintName(error: unknown): string | undefined;
```

**Returns**: The constraint name if available, `undefined` otherwise.

**Example**:

```typescript
try {
  await db.insert(users).values(userData);
} catch (error) {
  const constraint = extractConstraintName(error);
  if (constraint) {
    console.log(`Violated constraint: ${constraint}`);
  }
}
```

## Project Structure

```
libs/common/errors/
├── src/
│   ├── index.ts                          # Main exports
│   └── lib/
│       ├── common/                        # Domain-agnostic errors
│       │   ├── not-found.error.ts        # NotFoundError class
│       │   └── index.ts
│       └── database/                      # Database-specific errors
│           ├── unique-constraint.error.ts # UniqueConstraintError class
│           ├── helpers.ts                 # Database error utilities
│           └── index.ts
├── project.json
└── README.md
```

## Domain Organization

Errors are organized by domain to maintain clear separation:

- **common/**: Domain-agnostic errors that can be used across different parts of the application
  - `NotFoundError`: Generic "not found" error

- **database/**: Database-specific errors and utilities
  - `UniqueConstraintError`: Database unique constraint violations
  - `isUniqueConstraintError()`: Helper to identify unique constraint errors
  - `extractConstraintName()`: Helper to extract constraint names

Future domains may include:

- **auth/**: Authentication-specific errors
- **oauth/**: OAuth-specific errors
- **validation/**: Validation errors

## Best Practices

1. **Use Appropriate Error Types**: Choose the error class that best represents the failure scenario
2. **Include Context**: Provide meaningful entity names and IDs in error messages
3. **Preserve Original Errors**: Use the `cause` parameter to preserve the original error when wrapping
4. **Error Handling**: Always handle errors appropriately in your application layer
5. **Type Safety**: Use TypeScript's type narrowing with helper functions like `isUniqueConstraintError()`

## Example: Repository Pattern

```typescript
import {
  NotFoundError,
  UniqueConstraintError,
  isUniqueConstraintError,
  extractConstraintName,
} from '@qauth/errors';
import { db } from '@qauth/db';
import { users } from '@qauth/db/schema';

export async function createUser(data: NewUser) {
  try {
    const [user] = await db.insert(users).values(data).returning();
    return user;
  } catch (error) {
    if (isUniqueConstraintError(error)) {
      const constraint = extractConstraintName(error) || 'users_email_unique';
      throw new UniqueConstraintError(constraint, error);
    }
    throw error;
  }
}

export async function getUserById(id: string) {
  const user = await db.query.users.findFirst({
    where: eq(users.id, id),
  });

  if (!user) {
    throw new NotFoundError('User', id);
  }

  return user;
}
```

## Example: REST API Error Handling

Error classes include HTTP status codes for easy REST API integration:

```typescript
import { NotFoundError, UniqueConstraintError } from '@qauth/errors';
import Fastify from 'fastify';

fastify.get('/users/:id', async (request, reply) => {
  try {
    const user = await usersRepository.findByIdOrThrow(request.params.id);
    return { user };
  } catch (error) {
    if (error instanceof NotFoundError) {
      // Use the statusCode property for HTTP responses
      reply.code(error.statusCode).send({
        error: error.message,
        statusCode: error.statusCode,
      });
      return;
    }
    throw error;
  }
});

fastify.post('/users', async (request, reply) => {
  try {
    const user = await usersRepository.create(request.body);
    reply.code(201).send({ user });
  } catch (error) {
    if (error instanceof UniqueConstraintError) {
      // Use the statusCode property (409 Conflict)
      reply.code(error.statusCode).send({
        error: error.message,
        constraint: error.constraint,
        statusCode: error.statusCode,
      });
      return;
    }
    throw error;
  }
});
```

## Development

### Running Tests

```bash
nx test errors
```

### Linting

```bash
nx lint errors
```

### Type Checking

```bash
nx typecheck errors
```

## Related Libraries

- [`@qauth/db`](../../data-access/db/README.md): Database library that uses these errors in repositories

## Dependencies

This library has no external dependencies. It only uses built-in TypeScript/JavaScript features.

## License

Apache-2.0
