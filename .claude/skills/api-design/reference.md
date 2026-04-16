# API Design — Standards & Reference

Summary of REST and OpenAPI practices (2025–2026) and how QAuth applies them. Sources: REST API design guidance (Microsoft, Google), OpenAPI 3.1, RFC 6749/6750.

---

## 1. Resource-oriented REST

- **Nouns, not verbs**: URLs represent resources (`/users`, `/oauth/authorize`), not actions. Actions are expressed via HTTP method and optional body.
- **Plural collections**: Use plural for collections (`/users`, not `/user`). Singular for a single resource by ID when needed (`/users/:id`).
- **Lowercase, hyphens**: Path segments lowercase; use hyphens for multi-word segments (e.g. `resend-verification`).
- **Shallow nesting**: Prefer 2–3 levels (`/realms/:realmId/users`). Avoid deep trees; use query params for filtering.
- **Query params**: Use for filtering, sorting, pagination (`?page=1`, `?sort=createdAt`, `?status=active`). Keep body for create/update payloads.

---

## 2. HTTP methods and idempotency

| Method | Semantics        | Idempotent                 | Body           |
| ------ | ---------------- | -------------------------- | -------------- |
| GET    | Read resource(s) | Yes                        | No             |
| POST   | Create or action | No                         | Yes (optional) |
| PUT    | Replace resource | Yes                        | Yes            |
| PATCH  | Partial update   | No (often yes in practice) | Yes            |
| DELETE | Remove resource  | Yes                        | No             |

- **GET**: Safe and cacheable. No side effects. Use for read-only endpoints (e.g. health, authorize redirect params).
- **POST**: Use for create (register, token exchange) and non-idempotent actions (login, logout, refresh).
- **PUT/PATCH**: Use when updating resources; prefer PATCH for partial updates.

---

## 3. Status codes

**Success**

- **200 OK**: Request succeeded, body contains representation.
- **201 Created**: Resource created; optional `Location` header.
- **204 No Content**: Success, no body (e.g. logout).

**Client errors**

- **400 Bad Request**: Malformed request or validation failure (schema or semantic).
- **401 Unauthorized**: Missing or invalid authentication (e.g. invalid/expired token).
- **403 Forbidden**: Authenticated but not allowed (e.g. scope or permission).
- **404 Not Found**: Resource does not exist.
- **422 Unprocessable Entity**: Valid syntax but business-rule failure (e.g. duplicate email).
- **429 Too Many Requests**: Rate limit exceeded; use `Retry-After` when applicable.

**Server errors**

- **500 Internal Server Error**: Unexpected server error.
- **503 Service Unavailable**: Temporary overload or dependency down (e.g. health check failing).

Use one status per response; avoid overloading 400 for both validation and business errors when 422 is clearer.

---

## 4. Request/response bodies

- **Content-Type**: `application/json` for JSON. OAuth token endpoint uses `application/x-www-form-urlencoded` per RFC 6749.
- **Consistent shape**: Same resource type has same structure across endpoints (e.g. user object in register response and profile).
- **No redundant envelope**: Prefer direct payload (`{ "id", "email", ... }`) unless the API requires a wrapper (`{ "data": ..., "meta": ... }`). QAuth uses direct payloads.
- **OAuth token responses**: RFC 6749 §5.1 — `access_token`, `refresh_token`, `expires_in`, `token_type` (snake_case). Same shape for login, refresh, and token exchange in QAuth.

---

## 5. Error response body

Standardize error payload so clients can parse reliably:

- **error** (string): Human-readable message.
- **statusCode** (number): HTTP status (redundant but useful for clients).
- **code** (string, optional): Machine-readable code (e.g. `VALIDATION_ERROR`, `INVALID_CREDENTIALS`).
- **details** (optional): Validation errors (e.g. field-level messages).
- **feedback** (optional): E.g. password strength rules.
- **constraint** (optional): E.g. DB constraint name for 409/422.
- **retryAfter** (optional): For 429.

QAuth implements this in the global error handler; domain errors from `@qauth-labs/shared-errors` map to this shape.

---

## 6. Versioning

- **Path**: `/v1/users`, `/v2/users` — clear, cache-friendly, widely used.
- **Header**: `Accept: application/vnd.api+v1` or custom `X-API-Version` — keeps URLs stable.
- **Query**: `?version=1` — possible but discouraged (caching and tooling).

QAuth does not version yet. When adding versioning, prefer path prefix (e.g. `/v1/`) or a single version header; document in OpenAPI.

---

## 7. Security

- **Authentication**: Bearer token in `Authorization` header for protected routes. OAuth token endpoint uses client credentials in body or header per RFC.
- **HTTPS**: All non-local traffic over TLS.
- **Rate limiting**: Apply to login, token, register, and other sensitive endpoints. Return 429 with `Retry-After` when appropriate.
- **Stateless**: Each request carries enough context (token, client id). No server-side session storage for API auth beyond refresh token storage.
- **Sensitive data**: Never log passwords, tokens, or secrets. Use constant-time comparison and minimum response time for login/token to reduce timing leakage.

---

## 8. OpenAPI (Swagger)

- **OpenAPI 3.1**: Aligns with JSON Schema 2020-12; use when generating or consuming machine-readable specs.
- **Design-first**: Optional; define paths, parameters, and schemas in OpenAPI, then implement. QAuth uses Zod-first: schemas in code drive validation and can be used to generate OpenAPI.
- **fastify-type-provider-zod**: Integrates Zod with Fastify; compatible with `@fastify/swagger` for exporting OpenAPI from route schemas.

When adding OpenAPI export: document all public routes, request/response schemas, and error responses; include security schemes (e.g. Bearer, OAuth2).

---

## 9. QAuth conventions (summary)

| Item        | Convention                                                                         |
| ----------- | ---------------------------------------------------------------------------------- | --------------------------------------- |
| Schemas     | Zod in `app/schemas/`; `z.infer<>` for types                                       |
| Validators  | Zod v4: `z.email()`, `z.uuid()`, `z.url()` (standalone)                            |
| Route       | `fastify.withTypeProvider<ZodTypeProvider>().get                                   | post(..., { schema, config }, handler)` |
| Success     | 200/201/204 with typed body; no envelope                                           |
| Errors      | `@qauth-labs/shared-errors` + global handler → `{ error, statusCode, code?, ... }` |
| OAuth/token | snake_case per RFC 6749                                                            |
| App JSON    | camelCase                                                                          |
| Rate limit  | `config.rateLimit` with env-driven values                                          |
| Versioning  | Not used; use `/v1/` or header when added                                          |

These align with current REST and OpenAPI practice and with QAuth’s auth-server implementation.
