---
name: errors
description: Error handling for QAuth — domain errors from @qauth-labs/shared-errors, consistent error response shape, and security (no enumeration, no production stack traces). Use when throwing or handling errors, writing the global error handler, or working in apps/auth-server or libs/shared/errors.
---

# Error Handling (QAuth)

Standards-aligned error handling for the QAuth auth-server. Throw domain errors,
return a consistent JSON shape, and never leak sensitive data. Use this skill when
raising/handling errors or reviewing error-handling code.

## Use Domain Errors

Throw domain-specific errors from `@qauth-labs/shared-errors`:

```typescript
// ✅ GOOD: Domain error with statusCode
import { NotFoundError, InvalidCredentialsError } from '@qauth-labs/shared-errors';

if (!user) {
  throw new NotFoundError('User', userId);
}

if (!passwordValid) {
  throw new InvalidCredentialsError(); // Generic message prevents enumeration
}

// ❌ BAD: Generic Error or ad-hoc status codes
throw new Error('User not found');
reply.code(404).send({ error: 'Not found' });
```

## Error Response Shape

All errors return consistent JSON (handled by the global error handler):

- **Required**: `error` (string), `statusCode` (number)
- **Optional**: `code` (e.g. `INVALID_CREDENTIALS`), `feedback` (password rules),
  `constraint` (DB constraint), `retryAfter` (429), `details` (validation errors)

## Security

- **No sensitive data**: Never expose passwords, tokens, secrets, or internal
  paths in error messages.
- **Generic auth errors**: Use `InvalidCredentialsError` with the same message for
  "user not found" and "wrong password" to prevent user enumeration.
- **Stack traces**: Only in development (`NODE_ENV !== 'production'`); never in
  production responses.
- **Logging**: Log full error details server-side; sanitize client responses.

See the `security` skill for timing-safe comparison and minimum-response-time
rules that complement generic error messages.

## Error Class Pattern

```typescript
export class NotFoundError extends Error {
  readonly statusCode = 404;

  constructor(entity: string, id: string) {
    super(`${entity} with id ${id} not found`);
    this.name = 'NotFoundError';
    Object.setPrototypeOf(this, NotFoundError.prototype);
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, NotFoundError);
    }
  }
}
```

## Global Error Handler

Errors are caught by `apps/auth-server/src/app/plugins/error-handler.ts`:

- Maps domain errors to HTTP responses
- Handles Fastify validation errors (400 with `details`)
- Logs errors server-side
- Returns sanitized responses (no stack traces in production)

## Best Practices

- **Preserve cause**: Use the `cause` parameter when wrapping errors (e.g.
  `UniqueConstraintError(constraint, originalError)`).
- **Type safety**: Use `instanceof` checks or helper functions (e.g.
  `isUniqueConstraintError()`).
- **Don't catch and ignore**: Always handle or re-throw; let the global handler
  catch unhandled errors.

## Related

- Domain error classes: `libs/shared/errors/`
- Validation errors (400 shape): `validation` skill
- Auth/timing/secrets: `security` skill
