# API Reference

Hand-written reference for QAuth's HTTP endpoints. The **authoritative, always-current**
contract is the interactive **OpenAPI / Swagger UI at `/docs`** on any running
instance — this page is a stable, linkable companion.

For step-by-step flows with copy-paste `curl`, see the [OAuth 2.1 Flow](./oauth-flow.md)
guide; for working client code, see [Code Examples](./code-examples.md).

**Conventions**

- Base URL / issuer: `http://localhost:3000` (your `JWT_ISSUER`).
- First-party auth and client-management bodies are **JSON** (`application/json`)
  with **camelCase** fields. OAuth wire endpoints (`/oauth/*`) use
  **`application/x-www-form-urlencoded`** with **snake_case** per the RFCs.
- Access tokens are **EdDSA (Ed25519)** JWTs; verify against
  `GET /.well-known/jwks.json`.

## Error model

Errors share a single envelope:

```json
{ "error": "human-readable message", "statusCode": 400, "code": "OPTIONAL_CODE" }
```

Schema-validation failures use:

```json
{ "error": "Validation error", "code": "VALIDATION_ERROR", "statusCode": 400 }
```

OAuth endpoints additionally return the standard OAuth error codes documented in
[OAuth 2.1 Flow → Errors](./oauth-flow.md#errors) (e.g. `invalid_grant`,
`invalid_client`, `invalid_scope`, `invalid_target`).

| Status | Meaning                                                   |
| ------ | --------------------------------------------------------- |
| `400`  | Malformed request / validation error                      |
| `401`  | Missing, malformed, or invalid bearer token               |
| `403`  | Authenticated but not permitted (e.g. insufficient scope) |
| `404`  | Resource not found                                        |
| `409`  | Conflict (e.g. email already registered)                  |
| `429`  | Rate limited                                              |

---

## First-party authentication

Email/password endpoints for **end users of your own application**. Third-party
/ MCP clients use the [OAuth endpoints](#oauth-21) instead.

### `POST /auth/register`

Create a user account. A verification email is sent (the `mock` provider logs it).

**Request** (`application/json`)

| Field      | Type           | Required | Notes                                         |
| ---------- | -------------- | -------- | --------------------------------------------- |
| `email`    | string (email) | yes      |                                               |
| `password` | string         | yes      | Strength enforced server-side (zxcvbn score). |
| `realmId`  | string (uuid)  | no       | Defaults to the server's default realm.       |

**`201 Created`**

```json
{
  "id": "0190f7c2-...",
  "email": "dev@example.com",
  "emailVerified": false,
  "realmId": "0190f7c0-...",
  "createdAt": 1750000000000,
  "updatedAt": null
}
```

Errors: `400` (validation / weak password), `409` (email already registered),
`429` (rate limited).

### `POST /auth/login`

Authenticate with email/password and receive tokens directly (first-party).

**Request** (`application/json`): `{ "email": "...", "password": "..." }`

**`200 OK`**

```json
{
  "access_token": "eyJ…",
  "refresh_token": "a1b2…(64 hex)",
  "expires_in": 900,
  "token_type": "Bearer"
}
```

Errors: `400` (validation), `401` (invalid credentials), `429` (rate limited).
Renew the access token with the [`refresh_token` grant](./oauth-flow.md#refresh-token-rotation)
at `POST /oauth/token` — there is no separate refresh endpoint.

### `POST /auth/logout`

Revoke the caller's session/token.

**Headers**: `Authorization: Bearer <access_token>` (required).

**`200 OK`**: `{ "success": true, "message": "Successfully logged out" }`

Errors: `401` (missing/invalid bearer).

### `GET /auth/verify`

Confirm an email address from the link in the verification email.

**Query**: `token` — 64-char hex string.

**`200 OK`**: `{ "message": "...", "email": "dev@example.com" }`

Errors: `400` (malformed token), `404`/`400` (unknown or expired token).

### `POST /auth/resend-verification`

Re-send the verification email. Rate-limited per address (min-interval +
per-window caps).

**Request** (`application/json`): `{ "email": "dev@example.com" }`

**`200 OK`**: `{ "message": "..." }` — returned even for unknown addresses
(no account enumeration). Errors: `429` (too soon / over limit).

---

## OAuth 2.1

Full request/response detail and a worked end-to-end walkthrough live in the
[OAuth 2.1 Flow](./oauth-flow.md) guide. Contract summary:

| Endpoint                                                                    | Method | Body type | Purpose                                                                                     |
| --------------------------------------------------------------------------- | ------ | --------- | ------------------------------------------------------------------------------------------- |
| [`/oauth/authorize`](./oauth-flow.md#2-redirect-the-user-to-oauthauthorize) | GET    | query     | Start `authorization_code` + PKCE (browser)                                                 |
| [`/oauth/token`](./oauth-flow.md#3-exchange-the-code-for-tokens)            | POST   | form      | `authorization_code` / `refresh_token` / `client_credentials` / `token-exchange` (RFC 8693) |
| [`/oauth/introspect`](./oauth-flow.md#token-introspection-rfc-7662)         | POST   | form      | Token introspection (RFC 7662) — confidential clients only                                  |
| [`/oauth/userinfo`](./oauth-flow.md#userinfo-oidc)                          | GET    | —         | OIDC UserInfo (Bearer)                                                                      |
| [`/oauth/register`](./oauth-flow.md#dynamic-client-registration-rfc-7591)   | POST   | JSON      | Dynamic Client Registration (RFC 7591, open mode)                                           |

Key contract facts:

- `response_type` is `code` only; `code_challenge_method` is `S256` only (PKCE required).
- Tokens carry `iss`, `aud` (RFC 8707 resource binding), `exp`, `iat`, and `scope`.
- `client_credentials` tokens set `sub = client_id` and issue **no** refresh token.
- Scopes are **deny-by-default** (client allowlist; DCR clients capped to the
  realm's `DEFAULT_DYNAMIC_REGISTRATION_SCOPES`).
- The `urn:ietf:params:oauth:grant-type:token-exchange` grant (RFC 8693, ADR-007 §2)
  lets an **agent** client delegate on behalf of a user: `sub` stays the user and
  an `act` claim names the agent (nested for chained delegation). Agent-only and
  default-deny; scope/audience are preserved or narrowed, never widened. See the
  [Token Exchange](./oauth-flow.md#token-exchange--agent-on-behalf-of-delegation-rfc-8693)
  section and the [Agent Authorization guide](./agent-authorization.md).
- Dynamic Client Registration (`POST /oauth/register`) accepts the optional
  QAuth extension field `is_agent` (boolean, default `false`) marking the client
  as an AI agent; it is echoed back in the response. The flag is self-asserted
  and untrusted — see [Agent Authorization](./agent-authorization.md#1-agent-client-type-is_agent).

### Token response (`POST /oauth/token`, `200 OK`)

```json
{
  "access_token": "eyJ…",
  "refresh_token": "a1b2…", // omitted for client_credentials and token-exchange
  "expires_in": 900,
  "token_type": "Bearer",
  "scope": "openid profile email", // present when scopes granted
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token" // token-exchange only (RFC 8693 §2.2.1)
}
```

### Introspection response (`POST /oauth/introspect`, `200 OK`)

```json
{
  "active": true,
  "sub": "...",
  "client_id": "...",
  "scope": "mcp:read",
  "aud": "http://localhost:8088",
  "iss": "http://localhost:3000",
  "exp": 1750000000,
  "iat": 1749999100,
  "token_type": "Bearer"
}
```

An inactive/expired/unknown/wrong-audience token returns `{ "active": false }`.

### UserInfo response (`GET /oauth/userinfo`, `200 OK`)

```json
{ "sub": "...", "email": "dev@example.com", "email_verified": true }
```

`email`/`email_verified` are conditional: released only under the `email`
scope and only when a **verified** email attribute exists (ADR-002 trust
order `wallet > oidc_* > self_reported`). Otherwise both keys are **absent**
(never `null`). When present, `email_verified` is always `true`.

---

## Discovery

Unauthenticated, cacheable (`Cache-Control: public, max-age=3600`).

| Endpoint                                      | Returns                                      |
| --------------------------------------------- | -------------------------------------------- |
| `GET /.well-known/oauth-authorization-server` | OAuth 2.0 AS metadata (RFC 8414)             |
| `GET /.well-known/openid-configuration`       | OIDC Discovery 1.0 (superset of the above)   |
| `GET /.well-known/jwks.json`                  | JWKS — active EdDSA public key(s) (RFC 7517) |

Prefer discovering endpoint URLs from these documents over hard-coding paths.
The AS metadata advertises `resource_indicators_supported: true` and, when
enabled, `client_id_metadata_document_supported: true` (CIMD).

---

## Client management (`/api/clients`)

Developer-portal API for managing a developer's own OAuth clients. **JSON**,
**camelCase**, and authenticated with a developer **`Authorization: Bearer`**
access token (from [`POST /auth/login`](#post-authlogin)). Results are scoped to
the token subject's `developer_id`; the client secret is **never** returned.

### `GET /api/clients`

List the authenticated developer's OAuth clients.

**Headers**: `Authorization: Bearer <access_token>` (required).

**`200 OK`**

```json
{
  "clients": [
    {
      "id": "0190f7…",
      "clientId": "my-app",
      "name": "My App",
      "description": null,
      "redirectUris": ["http://localhost:5173/callback"],
      "scopes": ["openid", "profile"],
      "grantTypes": ["authorization_code", "refresh_token"],
      "responseTypes": ["code"],
      "tokenEndpointAuthMethod": "none",
      "enabled": true,
      "requirePkce": true,
      "createdAt": 1750000000000,
      "updatedAt": 1750000000000,
      "lastUsedAt": null
    }
  ]
}
```

A developer with no clients gets `{ "clients": [] }`. Errors: `401` (missing/invalid bearer).

> **Ownership & 404 semantics.** Every per-client route is scoped to the token
> subject's `developer_id`. A client that exists but is owned by another
> developer is reported as **`404 Not Found`** (not `403`) so the API never
> confirms the existence of clients the caller does not own.

### `POST /api/clients`

Create an OAuth client owned by the authenticated developer. The server
generates the `clientId` (UUID) and, for confidential clients, a 32-byte
`clientSecret`. **The plaintext `clientSecret` is returned in this response
only** — only its argon2id hash is stored, so it is unrecoverable afterwards.

**Headers**: `Authorization: Bearer <access_token>` (required).

**Body** (all besides `name` optional):

| Field                     | Type     | Default                                  | Notes                                                                                                                                         |
| ------------------------- | -------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`                    | string   | —                                        | Required, 1–255 chars.                                                                                                                        |
| `description`             | string   | `null`                                   |                                                                                                                                               |
| `redirectUris`            | string[] | `[]`                                     | Each validated (OAuth 2.1 §10.3 — `https` or loopback). **Required (≥1) for user-involving grants** (`authorization_code` / `refresh_token`). |
| `scopes`                  | string[] | `[]`                                     | Capped to the realm's allowed-scopes policy (same allowlist as dynamic registration); a scope outside it is rejected.                         |
| `grantTypes`              | string[] | `["authorization_code","refresh_token"]` | `authorization_code` / `refresh_token` / `client_credentials`.                                                                                |
| `responseTypes`           | string[] | `["code"]`                               | OAuth 2.1 only supports `code`.                                                                                                               |
| `tokenEndpointAuthMethod` | string   | `"none"`                                 | `none` (public) / `client_secret_post` / `client_secret_basic` / `private_key_jwt`.                                                           |

**Rate limit**: per-IP, shared budget with `POST /oauth/register`
(`REGISTER_CLIENT_RATE_LIMIT` / `REGISTER_CLIENT_RATE_WINDOW`) — create runs an
argon2id hash on every call, so the cap is mandatory (`429` on exceed).

**`201 Created`** (`Cache-Control: no-store`)

```json
{
  "id": "0190f7…",
  "clientId": "0190f7a0-…-uuid",
  "name": "My App",
  "description": null,
  "redirectUris": ["https://app.example.com/cb"],
  "scopes": ["openid"],
  "grantTypes": ["authorization_code", "refresh_token"],
  "responseTypes": ["code"],
  "tokenEndpointAuthMethod": "client_secret_post",
  "enabled": true,
  "requirePkce": true,
  "createdAt": 1750000000000,
  "updatedAt": 1750000000000,
  "lastUsedAt": null,
  "clientSecret": "a1b2c3…(64 hex chars, shown once)"
}
```

Public clients (`tokenEndpointAuthMethod: "none"`) get **no** `clientSecret`.
Errors: `400` (invalid `redirectUri`, inconsistent grant/response types, missing
`redirectUris` for a user-involving grant, or a scope outside the realm policy),
`401` (missing/invalid bearer, or a non-user token), `429` (rate limited).

### `GET /api/clients/:id`

Get one of the developer's clients. Safe fields only — never the secret.

**`200 OK`** — the same shape as a `GET /api/clients` list item.
Errors: `401`; `404` (not found or not owned).

### `PATCH /api/clients/:id`

Partially update a client. Any subset of: `name`, `description`,
`redirectUris`, `scopes`, `grantTypes`, `responseTypes`,
`tokenEndpointAuthMethod`, `enabled`. `clientId`, the secret, and
`developerId` are **immutable** here (unknown/immutable keys are ignored). The
_effective_ configuration (request value or persisted value) is re-validated:
grant/response-type consistency, a redirect URI for user-involving grants, and
the realm scope cap when `scopes` is changed.

**`200 OK`** — the updated client (safe fields, no secret).
Errors: `400` (validation / inconsistent config / disallowed scope / missing
redirect for a user-involving grant), `401`, `404`.

### `DELETE /api/clients/:id`

Delete a client. After deletion the client can no longer authenticate at the
token endpoint and cannot start new authorization flows. Note: already-issued
**access tokens are stateless JWTs** and remain valid until they expire;
short access-token lifetimes bound this window.

**`204 No Content`**. Errors: `401`; `404` (not found or not owned).

### `POST /api/clients/:id/regenerate-secret`

Issue a new `clientSecret`. The previous secret is invalidated immediately;
**the new plaintext secret is returned in this response only.**

**`200 OK`** (`Cache-Control: no-store`) — the client (safe fields) plus a
`clientSecret` string. Errors: `400` (public client — no secret to rotate),
`401`, `404`, `429` (rate limited — argon2id, same per-IP budget as create).

Clients may also be registered via [Dynamic Client Registration](./oauth-flow.md#dynamic-client-registration-rfc-7591)
(`POST /oauth/register`), CIMD, or the `seed-oauth-clients` script.

---

## See also

- [OAuth 2.1 Flow](./oauth-flow.md) — worked flows with `curl`.
- [Agent Authorization](./agent-authorization.md) — the agent-native layer
  (`is_agent`, Token Exchange, scope modes, step-up, audit).
- [Code Examples](./code-examples.md) — runnable Node/TS and browser clients.
- [MCP Quickstart](./mcp-quickstart.md) — protect an MCP server end-to-end.
