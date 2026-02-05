---
name: api-design
description: Designs and reviews HTTP APIs with resource-oriented REST, schema validation, and consistent error responses. Use when adding or changing auth-server routes, request/response schemas, or when the user asks about API design, versioning, or OpenAPI.
---

# API Design (QAuth)

Standards-aligned HTTP API design for QAuth auth-server. APIs are resource-oriented, schema-validated with Zod, and return consistent success and error payloads. Use this skill when defining new endpoints, schemas, or reviewing API contracts.

## When to Use This Skill

- Adding or changing routes in `apps/auth-server`
- Defining or updating request/response schemas (Zod)
- Designing error response shape or status codes
- Questions about REST conventions, versioning, or OpenAPI

## Quick Reference

| Concern          | QAuth pattern                                                                      |
| ---------------- | ---------------------------------------------------------------------------------- |
| **Validation**   | Zod schemas in `app/schemas/`; `fastify-type-provider-zod` on routes               |
| **Route schema** | `schema: { body?, querystring?, params?, response: { 200: schema } }`              |
| **Success**      | 200/201/204 with typed body; no extra envelope unless needed                       |
| **Errors**       | `{ error, statusCode, code?, feedback?, constraint?, retryAfter?, details? }`      |
| **OAuth tokens** | RFC 6749: snake_case (`access_token`, `refresh_token`, `expires_in`, `token_type`) |
| **Other JSON**   | camelCase for app-specific fields (e.g. `emailVerified`, `realmId`)                |
| **Versioning**   | Not in use yet; prefer path `/v1/` or header when introduced                       |

## Route Structure (QAuth)

1. **Schemas first**  
   Define Zod schemas in `app/schemas/` (e.g. `auth.ts`, `oauth.ts`, `common.ts`). Export schema and inferred type (`z.infer<typeof schema>`). Use `z.email()`, `z.uuid()`, `z.url()` (Zod v4 standalone validators).

2. **Register schema on route**  
   Use `fastify.withTypeProvider<ZodTypeProvider>().get|post|...(path, { schema, config }, handler)`. Set `schema.body`, `schema.querystring`, `schema.params`, and `schema.response` (e.g. `response: { 200: responseSchema }`). Fastify validates and types request/response.

3. **Rate limiting**  
   Use `config.rateLimit` with `max`, `timeWindow`, and optional `keyGenerator` (e.g. by `request.ip`). Values come from env (e.g. `env.LOGIN_RATE_LIMIT`).

4. **Errors**  
   Throw domain errors from `@qauth/shared-errors`. Error handler maps them to HTTP status and the standard error JSON shape. For validation, rely on Fastify validation (schema); it produces 400 with `details`.

5. **Security**  
   Keep handlers stateless. Use constant-time checks and minimum response time where needed (e.g. login). Do not log secrets or tokens.

## HTTP Methods and Status Codes

| Method | Use                                                |
| ------ | -------------------------------------------------- |
| GET    | Read resource or list; idempotent, cacheable       |
| POST   | Create resource or action (login, token, register) |
| PUT    | Replace resource (idempotent)                      |
| PATCH  | Partial update                                     |
| DELETE | Remove resource                                    |

| Status | Use                                                               |
| ------ | ----------------------------------------------------------------- |
| 200    | Success with body                                                 |
| 201    | Created (e.g. register)                                           |
| 204    | Success, no body                                                  |
| 400    | Bad request / validation error                                    |
| 401    | Unauthorized (missing or invalid auth)                            |
| 403    | Forbidden (valid auth, insufficient permission)                   |
| 404    | Not found                                                         |
| 422    | Unprocessable entity (semantic validation)                        |
| 429    | Too many requests (rate limit; set `Retry-After` when applicable) |
| 500    | Internal server error                                             |
| 503    | Service unavailable (e.g. health unhealthy)                       |

## Error Response Shape

All errors use a common shape (see `error-handler.ts` and `common.ts`):

- **Required**: `error` (string), `statusCode` (number).
- **Optional**: `code` (e.g. `VALIDATION_ERROR`), `feedback` (e.g. password rules), `constraint` (e.g. unique violation), `retryAfter` (429), `details` (validation details). In development, `stack` may be included for 500.

Use custom error classes from `@qauth/shared-errors` so the handler can set status and optional fields consistently.

## Naming Conventions

- **OAuth / RFC 6749**: Use snake_case for token endpoint and auth params (`access_token`, `refresh_token`, `expires_in`, `token_type`, `grant_type`, `client_id`, etc.).
- **App-specific JSON**: Use camelCase (`emailVerified`, `realmId`, `createdAt`).
- **URLs**: Lowercase, plural nouns for resources (`/health`, `/login`, `/oauth/authorize`, `/oauth/token`). Keep nesting shallow (e.g. 2–3 levels).

## Checklist for New Endpoints

- [ ] Zod schema(s) in `app/schemas/` with exported type
- [ ] Route registered with `schema.body` / `querystring` / `params` and `schema.response`
- [ ] Rate limit via `config.rateLimit` where appropriate
- [ ] Domain errors thrown from `@qauth/shared-errors`; no ad-hoc status codes in handler
- [ ] OAuth-related payloads use RFC snake_case; other JSON uses camelCase
- [ ] No secrets or tokens in logs

## Additional Resources

- REST and OpenAPI standards: [reference.md](reference.md)
- Schemas: `apps/auth-server/src/app/schemas/`
- Error handler: `apps/auth-server/src/app/plugins/error-handler.ts`
- Route examples: `apps/auth-server/src/app/routes/auth/login.ts`, `apps/auth-server/src/app/routes/oauth/token.ts`
