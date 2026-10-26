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

The global error handler (`apps/auth-server/src/app/plugins/error-handler.ts`)
answers in one of two formats, chosen by the route's `config.errorFormat`
(ADR-019 Decision 7, #513):

- **`problem`** (the default): an RFC 9457 document, `application/problem+json`,
  with `type`, `title`, `status`, `detail`, `instance`, a stable lower-case `code`
  and `trace_id` (the request id); `errors[]` (`pointer`, `message`) for a
  validation failure and for weak-password feedback under `/password`.
- **`oauth`**, set on the OAuth protocol endpoints only (token, authorize,
  introspect, revoke, register, userinfo, the wallet-facing OID4VP endpoints):
  `{ error, error_description? }` and nothing else.

Which `code` and which OAuth `error` a domain error class answers is set once, in
`apps/auth-server/src/app/api-conventions/error-classes.ts`; a new class in
`@qauth-labs/shared-errors` needs an entry there (a test fails without one). A
class a route or a server library defines with a `statusCode` (the SSF
transmitter's, `SignInRequiredError`) goes in `APP_ERROR_CLASSES` there, with a
published code for its status; a test fails without one. A route never sends an
error body of its own: it throws, and the handler answers.
An OAuth error class carries its token as its `message` and its prose in
`errorDescription`. A refusal that several routes raise comes from one helper in
the module that owns it (e.g. `helpers/token-subject.ts`), so it reads one way.
Tests assert `code` (problem) or `error` (OAuth) and the status, never the
wording.

## Security

- **No sensitive data**: Never expose passwords, tokens, secrets, or internal
  paths in error messages.
- **Generic auth errors**: Use `InvalidCredentialsError` with the same message for
  "user not found" and "wrong password" to prevent user enumeration.
- **Stack traces**: never in a response. A 5xx carries no `detail`; its
  `trace_id` leads to the log line.
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
