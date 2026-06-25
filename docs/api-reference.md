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

| Endpoint                                                                    | Method | Body type | Purpose                                                       |
| --------------------------------------------------------------------------- | ------ | --------- | ------------------------------------------------------------- |
| [`/oauth/authorize`](./oauth-flow.md#2-redirect-the-user-to-oauthauthorize) | GET    | query     | Start `authorization_code` + PKCE (browser)                   |
| [`/oauth/token`](./oauth-flow.md#3-exchange-the-code-for-tokens)            | POST   | form      | `authorization_code` / `refresh_token` / `client_credentials` |
| [`/oauth/introspect`](./oauth-flow.md#token-introspection-rfc-7662)         | POST   | form      | Token introspection (RFC 7662) — confidential clients only    |
| [`/oauth/userinfo`](./oauth-flow.md#userinfo-oidc)                          | GET    | —         | OIDC UserInfo (Bearer)                                        |
| [`/oauth/register`](./oauth-flow.md#dynamic-client-registration-rfc-7591)   | POST   | JSON      | Dynamic Client Registration (RFC 7591, open mode)             |

Key contract facts:

- `response_type` is `code` only; `code_challenge_method` is `S256` only (PKCE required).
- Tokens carry `iss`, `aud` (RFC 8707 resource binding), `exp`, `iat`, and `scope`.
- `client_credentials` tokens set `sub = client_id` and issue **no** refresh token.
- Scopes are **deny-by-default** (client allowlist; DCR clients capped to the
  realm's `DEFAULT_DYNAMIC_REGISTRATION_SCOPES`).

### Token response (`POST /oauth/token`, `200 OK`)

```json
{
  "access_token": "eyJ…",
  "refresh_token": "a1b2…", // omitted for client_credentials
  "expires_in": 900,
  "token_type": "Bearer",
  "scope": "openid profile email" // present when scopes granted
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

### Planned — gated on the T2 milestone

The write operations are not yet implemented (tracked under
[T2 — Agent-native authZ](https://github.com/qauth-labs/qauth/milestones)):

| Endpoint                             | Method | Issue                                                |
| ------------------------------------ | ------ | ---------------------------------------------------- |
| `/api/clients`                       | POST   | [#86](https://github.com/qauth-labs/qauth/issues/86) |
| `/api/clients/:id`                   | GET    | [#87](https://github.com/qauth-labs/qauth/issues/87) |
| `/api/clients/:id`                   | PATCH  | [#88](https://github.com/qauth-labs/qauth/issues/88) |
| `/api/clients/:id`                   | DELETE | [#89](https://github.com/qauth-labs/qauth/issues/89) |
| `/api/clients/:id/regenerate-secret` | POST   | [#90](https://github.com/qauth-labs/qauth/issues/90) |

Until they land, register clients via [Dynamic Client Registration](./oauth-flow.md#dynamic-client-registration-rfc-7591)
(`POST /oauth/register`), CIMD, or the `seed-oauth-clients` script.

---

## See also

- [OAuth 2.1 Flow](./oauth-flow.md) — worked flows with `curl`.
- [Code Examples](./code-examples.md) — runnable Node/TS and browser clients.
- [MCP Quickstart](./mcp-quickstart.md) — protect an MCP server end-to-end.
