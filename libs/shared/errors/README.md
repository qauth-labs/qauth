# QAuth Errors Library

Centralized error classes and error handling utilities for the QAuth platform. This library provides domain-specific error types organized by their use case.

## Overview

The `@qauth-labs/shared-errors` library provides a comprehensive set of error classes and utilities for consistent error handling across the QAuth platform. Errors are organized by domain (common, database, etc.) to maintain clear separation of concerns.

## Features

- **Domain-Organized Errors**: Errors grouped by domain (common, database, etc.)
- **Type-Safe Error Classes**: Custom error classes with proper TypeScript typing
- **Database Error Helpers**: Utilities for identifying and handling database-specific errors
- **Consistent Error Handling**: Standardized error messages and error structure across the platform

## Installation

This library is part of the QAuth monorepo and is automatically available to other projects within the workspace.

```typescript
import { NotFoundError, UniqueConstraintError } from '@qauth-labs/shared-errors';
```

## Usage

### Authentication Errors

Authentication-specific errors for JWT, tokens, and credentials.

```typescript
import {
  JWTExpiredError,
  JWTInvalidError,
  InvalidCredentialsError,
  TokenExpiredError,
  TokenAlreadyUsedError,
  WeakPasswordError,
  EmailNotVerifiedError,
  EmailAlreadyVerifiedError,
} from '@qauth-labs/shared-errors';

// JWT verification
try {
  const payload = await verifyAccessToken(token, publicKey);
} catch (error) {
  if (error instanceof JWTExpiredError) {
    // Token has expired - prompt refresh
    // error.statusCode === 401
  } else if (error instanceof JWTInvalidError) {
    // Token is malformed or has wrong signature
    // error.statusCode === 401
  }
}

// Login flow. Since ADR-002 (#230) the hash lives on the credential
// (`credential_data.password_hash`), and verification state on the credential
// too — the `users` row carries neither.
if (!credential || !(await verifyPassword(credential.credentialData.password_hash, password))) {
  throw new InvalidCredentialsError(); // 401
}

if (!credential.credentialData.email_verified) {
  throw new EmailNotVerifiedError(); // 403
}

// Token verification
if (token.used) {
  throw new TokenAlreadyUsedError(); // 400
}

if (token.expiresAt < Date.now()) {
  throw new TokenExpiredError(); // 401
}

// Password validation
if (passwordScore < minScore) {
  throw new WeakPasswordError('Password is too weak'); // 400
}
```

### Common Errors

Common errors are domain-agnostic and can be used across different parts of the application.

#### NotFoundError

Thrown when an entity is not found in the database or any data store.

```typescript
import { NotFoundError } from '@qauth-labs/shared-errors';

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
} from '@qauth-labs/shared-errors';

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
import { isUniqueConstraintError, extractConstraintName } from '@qauth-labs/shared-errors';

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

**Location**: `@qauth-labs/shared-errors` (from `common` domain)

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

**Location**: `@qauth-labs/shared-errors` (from `database` domain)

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

> **Note — don't read `error.code` directly.** Since drizzle-orm `>=0.30`, the raw
> `pg` error is wrapped in a `DrizzleQueryError`, so the SQLSTATE `code` and the
> `constraint`/`detail`/`severity` fields live on `error.cause`, not the top-level
> error. `isUniqueConstraintError` and `extractConstraintName` walk the `.cause`
> chain (skipping any unrelated wrappers that carry their own non-SQLSTATE `code`,
> such as Fastify `FST_ERR_*`) to find the real Postgres error. Always go through
> these helpers rather than inspecting `error.code` yourself — the value you want
> may be several links down the cause chain.

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
libs/shared/errors/
├── src/
│   ├── index.ts                          # Main exports
│   └── lib/
│       ├── auth/                          # Authentication errors
│       │   ├── email-already-verified.error.ts
│       │   ├── email-not-verified.error.ts
│       │   ├── invalid-credentials.error.ts
│       │   ├── invalid-token.error.ts
│       │   ├── jwt-expired.error.ts
│       │   ├── jwt-invalid.error.ts
│       │   ├── token-already-used.error.ts
│       │   ├── token-expired.error.ts
│       │   ├── weak-password.error.ts
│       │   └── index.ts
│       ├── common/                        # Domain-agnostic errors
│       │   ├── bad-request.error.ts
│       │   ├── not-found.error.ts
│       │   ├── too-many-requests.error.ts
│       │   └── index.ts
│       └── database/                      # Database-specific errors
│           ├── unique-constraint.error.ts
│           ├── helpers.ts
│           └── index.ts
├── project.json
└── README.md
```

## Domain Organization

Errors are organized by domain to maintain clear separation:

- **auth/**: Authentication-specific errors
  - `EmailAlreadyVerifiedError`: Email is already verified (400)
  - `EmailNotVerifiedError`: Email not verified yet (403)
  - `InvalidCredentialsError`: Invalid email or password (401)
  - `InvalidTokenError`: Token is invalid or malformed (401)
  - `JWTExpiredError`: JWT token has expired (401)
  - `JWTInvalidError`: JWT token is invalid (401)
  - `TokenAlreadyUsedError`: Token has already been used (400)
  - `TokenExpiredError`: Token has expired (401)
  - `WeakPasswordError`: Password does not meet requirements (400)

- **common/**: Domain-agnostic errors
  - `BadRequestError`: Generic bad request error (400)
  - `NotFoundError`: Entity not found (404)
  - `TooManyRequestsError`: Rate limit exceeded (429)

- **database/**: Database-specific errors and utilities
  - `UniqueConstraintError`: Database unique constraint violations (409)
  - `isUniqueConstraintError()`: Helper to identify unique constraint errors
  - `extractConstraintName()`: Helper to extract constraint names

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
} from '@qauth-labs/shared-errors';
// `@qauth-labs/infra-db` exports a factory plus a `schema` namespace — there is
// no `db` singleton and no `/schema` subpath export.
import { createDatabase, schema } from '@qauth-labs/infra-db';

const { db } = createDatabase({ connectionString: process.env.DATABASE_URL });
const { users } = schema;

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

## How the Auth Server Answers These Errors

A route throws the error and lets the auth server's global error handler
(`apps/auth-server/src/app/plugins/error-handler.ts`) answer it; it never builds
an error body itself:

```typescript
import { NotFoundError } from '@qauth-labs/shared-errors';

fastify.get('/api/clients/:id', async (request) => {
  const client = await fastify.repositories.oauthClients.findById(request.params.id);
  if (!client) throw new NotFoundError('OAuthClient', request.params.id);
  return client;
});
```

The handler answers in the route's error format (#513):

- every route that is not an OAuth protocol endpoint answers an RFC 9457 problem
  document (`application/problem+json`) whose `code` is the class's problem code,
  `not_found` here;
- an OAuth protocol endpoint answers `{ error, error_description? }`, where an
  OAuth class (`InvalidGrantError`, `InvalidClientMetadataError`, …) names its own
  token as its `message` and its prose as `errorDescription`.

Each class is mapped to its problem code and its OAuth `error` once, in
`apps/auth-server/src/app/api-conventions/error-classes.ts`. A new class in this
package needs an entry there: a test fails when one is missing. The error classes
a route or a server library defines itself (the SSF transmitter's, the
auth server's `SignInRequiredError`) are mapped in the same file. The codes are
published on the docs site's [Problem types](https://docs.qauth.dev/reference/problem-types/)
page and are part of the 1.0 promise. The handler never sends a
`UniqueConstraintError`'s constraint name or a 5xx's message to the caller.

## Development

### Running Tests

```bash
nx test shared-errors
```

### Linting

```bash
nx lint shared-errors
```

### Type Checking

```bash
nx typecheck shared-errors
```

## Related Libraries

- [`@qauth-labs/infra-db`](../../infra/db/README.md): Database library that uses these errors in repositories

## Dependencies

This library has no external dependencies. It only uses built-in TypeScript/JavaScript features.

## License

Apache-2.0
