---
name: validation
description: Input validation and Zod v4 schemas for QAuth — standalone format validators (z.email/z.uuid/z.url, not the deprecated string-method form), schema organization, length limits, and normalize-before-validate. Use when adding or reviewing Zod schemas, route validation, or config validation.
---

# Validation (QAuth)

Input validation for the QAuth auth-server using **Zod v4**. Validate at the route
boundary (fail fast), organize schemas consistently, and use the standalone Zod v4
validators. Use this skill when defining or reviewing schemas.

## Zod v4 Validators

This project uses **Zod v4**, where many format validators are **standalone
functions**, not string methods. Do **not** use the deprecated string-method form.

| Use         | Not                  |
| ----------- | -------------------- |
| `z.email()` | `z.string().email()` |
| `z.uuid()`  | `z.string().uuid()`  |
| `z.url()`   | `z.string().url()`   |

Optional error message: `z.email('Invalid email format')`,
`z.uuid('Invalid realm ID format')`, `z.url('Must be a valid URL')`.

Also standalone in Zod v4: `z.httpUrl()`, `z.hostname()`, `z.jwt()`,
`z.iso.date()`, `z.iso.datetime()`, `z.ipv4()`, `z.ipv6()`, `z.hex()`,
`z.base64()`, etc. See [zod.dev/api](https://zod.dev/api) under "String formats."
If you learn another Zod v4 standalone validator, use it consistently and do not
fall back to the old string-method form.

Export the schema and its inferred type together:

```typescript
export type RequestType = z.infer<typeof requestSchema>;
```

## Schema Organization

- **API schemas**: `apps/auth-server/src/app/schemas/` (e.g. `auth.ts`, `oauth.ts`,
  `common.ts`)
- **Config schemas**: `libs/server/config/src/lib/schemas/` (env validation)
- **Shared validators**: `libs/shared/validation/` (email normalization, password
  strength)

## Security and Best Practices

- **Validate all inputs**: body, query params, headers, and response shape. Never
  trust client input.
- **Fail fast**: validation happens at the route level via the Fastify schema;
  invalid requests return 400 before the handler runs.
- **Normalize before validation/use**: email normalization (`normalizeEmail`)
  happens after format validation but before storage/query.
- **Specific formats**: use regex for exact formats (e.g. hex tokens
  `/^[0-9a-fA-F]{64}$/`, PKCE verifiers `/^[A-Za-z0-9._~-]{43,128}$/`).
- **Length limits**: set `.min()` and `.max()` on strings to prevent DoS (e.g.
  `state: z.string().max(255).optional()`).
- **Password strength**: use `zxcvbn` via `@qauth-labs/shared-validation`; return
  feedback for weak passwords.

## Route Integration

```typescript
// ✅ GOOD: Schema registered on the route (validates before the handler)
fastify.withTypeProvider<ZodTypeProvider>().post(
  '/login',
  {
    schema: {
      body: loginSchema,
      response: { 200: loginResponseSchema },
    },
  },
  async (request, reply) => {
    // request.body is typed and validated
  }
);

// ❌ BAD: Manual validation inside the handler (too late)
fastify.post('/login', async (request, reply) => {
  const body = loginSchema.parse(request.body);
});
```

## Example Schema

```typescript
export const registerSchema = z.object({
  email: z.email('Invalid email format'),
  password: z.string(),
  realmId: z.uuid('Invalid realm ID format').optional(),
});

export type RegisterRequest = z.infer<typeof registerSchema>;
```

## Related

- Route/type-provider setup and Fastify schema wiring: `fastify` skill
- Validation-error response shape (400 with `details`): `errors` skill
- Rate limiting, timing, secrets: `security` skill
