---
title: API Reference
description: Hand-written reference for every path in QAuth's committed OpenAPI spec.
sidebar:
  order: 4
lastVerified: '2026-07-27'
---

Hand-written reference for QAuth's HTTP endpoints. The **authoritative, always-current**
contract is the interactive OpenAPI / Swagger UI served at /docs on any running
instance — this page is a stable, linkable companion. The same contract is also
published as a static file: [`openapi.json`](https://docs.qauth.dev/openapi.json).

For step-by-step flows with copy-paste `curl`, see the [OAuth 2.1 Flow](/integrate/oauth-flow/)
guide; for working client code, see [Code Examples](/integrate/code-examples/); for the
login/consent/resume screens an end user sees, see [Hosted UI](/integrate/hosted-ui/).

**Conventions**

- Base URL / issuer: `http://localhost:3000` (your `JWT_ISSUER`).
- First-party auth, client-management, and hosted-UI bodies are **JSON**
  (`application/json`) with **camelCase** fields. OAuth wire endpoints (the OAuth 2.1
  section below) use **`application/x-www-form-urlencoded`** with **snake_case** per the RFCs.
- Access tokens are **EdDSA (Ed25519)** JWTs; verify against
  `GET /.well-known/jwks.json`.
- Path parameters are written in OpenAPI's `{param}` style below (matching
  `openapi.json`), not the `:param` style the Fastify route files use internally.

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
[OAuth 2.1 Flow → Errors](/integrate/oauth-flow/#errors) (e.g. `invalid_grant`,
`invalid_client`, `invalid_scope`, `invalid_target`).

| Status | Meaning                                                   |
| ------ | --------------------------------------------------------- |
| `400`  | Malformed request / validation error                      |
| `401`  | Missing, malformed, or invalid bearer token / session     |
| `403`  | Authenticated but not permitted (e.g. insufficient scope) |
| `404`  | Resource not found                                        |
| `409`  | Conflict (e.g. email already registered)                  |
| `429`  | Rate limited                                              |

---

## System

Unauthenticated operational endpoints.

### `GET /`

Root endpoint. Returns a fixed greeting to verify the server is running.

**`200 OK`**: `{ "message": "Hello API" }`

### `GET /health`

Liveness/readiness probe. Checks database and Redis connectivity.

**`200 OK`** (both dependencies reachable):

```json
{
  "status": "ok",
  "timestamp": "2026-07-27T00:00:00.000Z",
  "services": { "database": "connected", "redis": "connected" }
}
```

**`503 Service Unavailable`** — same shape with `status: "unhealthy"` and the
unreachable dependency reported `"disconnected"`.

### `GET /metrics`

Prometheus text-exposition metrics: default Node.js/process metrics plus
application counters (login attempts by outcome, tokens issued by type and
grant). No authentication — put it behind network-level access control in
production.

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
Renew the access token with the [`refresh_token` grant](/integrate/oauth-flow/#refresh-token-rotation)
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
[OAuth 2.1 Flow](/integrate/oauth-flow/) guide. Contract summary:

| Endpoint                                                                           | Method    | Body type    | Purpose                                                                                                                                            |
| ---------------------------------------------------------------------------------- | --------- | ------------ | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`/oauth/authorize`](/integrate/oauth-flow/#2-redirect-the-user-to-oauthauthorize) | GET, POST | query / form | Start `authorization_code` + PKCE. POST mirrors GET with form-encoded params (OIDC Core §3.1.2.1) — browser-navigated either way, not an API call. |
| [`/oauth/token`](/integrate/oauth-flow/#3-exchange-the-code-for-tokens)            | POST      | form         | `authorization_code` / `refresh_token` / `client_credentials` / `token-exchange` (RFC 8693)                                                        |
| [`/oauth/introspect`](/integrate/oauth-flow/#token-introspection-rfc-7662)         | POST      | form         | Token introspection (RFC 7662) — confidential clients only                                                                                         |
| [`/oauth/userinfo`](/integrate/oauth-flow/#userinfo-oidc)                          | GET, POST | —            | OIDC UserInfo (Bearer header, or POST with a form-encoded `access_token`, RFC 6750 §2.2)                                                           |
| [`/oauth/register`](/integrate/oauth-flow/#dynamic-client-registration-rfc-7591)   | POST      | JSON         | Dynamic Client Registration (RFC 7591, open mode)                                                                                                  |
| `/oauth/revoke`                                                                    | POST      | form         | Token revocation (RFC 7009)                                                                                                                        |

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
  [Token Exchange](/integrate/oauth-flow/#token-exchange--agent-on-behalf-of-delegation-rfc-8693)
  section and the [Agent Authorization guide](/integrate/agent-authorization/).
- Dynamic Client Registration (`POST /oauth/register`) accepts the optional
  QAuth extension field `is_agent` (boolean, default `false`) marking the client
  as an AI agent; it is echoed back in the response. The flag is self-asserted
  and untrusted — see [Agent Authorization](/integrate/agent-authorization/#1-agent-client-type-is_agent).

### Token response (`POST /oauth/token`, `200 OK`)

```json
{
  "access_token": "eyJ…",
  "refresh_token": "a1b2…", // omitted for client_credentials and token-exchange
  "id_token": "eyJ…", // authorization_code grant only, when `openid` was granted
  "expires_in": 900,
  "token_type": "Bearer",
  "scope": "openid profile email", // present when scopes granted
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token" // token-exchange only (RFC 8693 §2.2.1)
}
```

`id_token` is a separate, client-audienced (`aud` = your `client_id`) EdDSA JWT
asserting the sign-in event: `sub`, `nonce` (when sent), `auth_time`, `name`
(when set on the user, not gated by the `profile` scope), and `email` /
`email_verified` (only under the `email` scope, same trust-ordered resolution
as the [UserInfo response](#userinfo-response-getpost-oauthuserinfo-200-ok)
below). Only the `authorization_code` grant issues one; `refresh_token` does
not reissue it. See
[ID token claims](/integrate/oauth-flow/#id-token-claims-oidc) for the full
list.

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

### UserInfo response (`GET|POST /oauth/userinfo`, `200 OK`)

```json
{ "sub": "...", "email": "dev@example.com", "email_verified": true }
```

`email`/`email_verified` are conditional: released only under the `email`
scope and only when a **verified** email attribute exists (ADR-002 trust
order `wallet > oidc_* > self_reported`). Otherwise both keys are **absent**
(never `null`). When present, `email_verified` is always `true`. The `POST`
form accepts the access token either as a Bearer header or as a form-encoded
`access_token` field (RFC 6750 §2.2).

### `POST /oauth/revoke`

RFC 7009 token revocation. Confidential client authentication required
(`client_secret_basic` / `client_secret_post`, the same as introspection).

**Request** (form-urlencoded): `token` (required), `token_type_hint`
(`access_token` | `refresh_token`, optional/advisory), plus client credentials
if not sent via HTTP Basic.

**`200 OK`**, empty body — **always**, per RFC 7009 §2.2. A refresh token
revokes its whole rotation family; an access token is denylisted by `jti` for
its remaining lifetime. A token the caller doesn't own, or an unknown/invalid
token, is a silent no-op (not an error), so the endpoint cannot be used to
probe whether a token exists. The only non-`200` outcome is a client
authentication failure (`invalid_client`).

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

## Hosted UI

Three server-rendered, cookie-authenticated pages back the browser leg of
`authorization_code` — see [Hosted UI](/integrate/hosted-ui/) for the full
behaviour, including the pending-authorization mechanics behind the login
bounce.

| Endpoint              | Method    | Purpose                                                                |
| --------------------- | --------- | ---------------------------------------------------------------------- |
| `/ui/login`           | GET, POST | Session-cookie login page and form submission                          |
| `/ui/consent`         | GET, POST | OAuth consent screen and decision submission                           |
| `/ui/resume/{handle}` | GET       | Resume a pending authorization after login (single-use, 10-minute TTL) |

---

## Consents (`/consents/`)

Lets a signed-in user manage their own OAuth consent grants. **Cookie-authed**
(`__Host-qauth_session`), not Bearer — there is no first-party access-token path
here, because consent management is inherently a same-origin, user-present
operation.

### `GET /consents/`

List the signed-in user's active consents. The response also carries a
per-session CSRF token that **must** be echoed back as `X-CSRF-Token` on
`DELETE /consents/{id}`.

**`200 OK`**

```json
{
  "consents": [
    {
      "id": "...",
      "clientId": "...",
      "clientName": "My App",
      "scopes": ["openid"],
      "grantedAt": 1750000000000
    }
  ],
  "csrfToken": "..."
}
```

Errors: `401` (no/invalid session) — returns `{ "consents": [] }` with no `csrfToken`.

### `DELETE /consents/{id}`

Revoke one consent owned by the signed-in user.

**Headers**: `X-CSRF-Token: <csrfToken from GET /consents/>` (required).

**`204 No Content`**. Errors: `400` (`invalid_csrf_token` — missing or
mismatched `X-CSRF-Token`; the first outcome you'll hit if the header isn't
wired up yet), `401` (no/invalid session), `404` (consent does not exist or
is not owned by the caller).

---

## Client management (`/api/clients/`)

Developer-portal API for managing a developer's own OAuth clients. **JSON**,
**camelCase**, and authenticated with a developer **`Authorization: Bearer`**
access token (from [`POST /auth/login`](#post-authlogin)). Results are scoped to
the token subject's `developer_id`; the client secret is **never** returned.

### `GET /api/clients/`

List the authenticated developer's OAuth clients.

**Headers**: `Authorization: Bearer <access_token>` (required).

**`200 OK`**

```json
{
  "clients": [
    {
      "id": "0190f7…",
      "clientId": "0190f7a0-…-uuid",
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

### `POST /api/clients/`

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

### `GET /api/clients/{id}`

Get one of the developer's clients. Safe fields only — never the secret.

**`200 OK`** — the same shape as a `GET /api/clients/` list item.
Errors: `401`; `404` (not found or not owned).

### `PATCH /api/clients/{id}`

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

### `DELETE /api/clients/{id}`

Delete a client. After deletion the client can no longer authenticate at the
token endpoint and cannot start new authorization flows. Note: already-issued
**access tokens are stateless JWTs** and remain valid until they expire;
short access-token lifetimes bound this window.

**`204 No Content`**. Errors: `401`; `404` (not found or not owned).

### `POST /api/clients/{id}/regenerate-secret`

Issue a new `clientSecret`. The previous secret is invalidated immediately;
**the new plaintext secret is returned in this response only.**

**`200 OK`** (`Cache-Control: no-store`) — the client (safe fields) plus a
`clientSecret` string. Errors: `400` (public client — no secret to rotate),
`401`, `404`, `429` (rate limited — argon2id, same per-IP budget as create).

Clients may also be registered via [Dynamic Client Registration](/integrate/oauth-flow/#dynamic-client-registration-rfc-7591)
(`POST /oauth/register`), CIMD, or the `seed-oauth-clients` script.

---

## API keys (`/api/clients/{clientId}/api-keys`)

Static, long-lived developer API keys scoped to one of the developer's own
OAuth clients — an alternative to `client_credentials` for **development-only**
use. Same Bearer developer authentication and ownership/404 rules as client
management, above.

> **Environment-gated (ADR-008 §6).** Minting a key is permitted only while the
> client resolves to a **development** environment; a staging/production (or
> unset-environment) client is refused with `403`. Use the OAuth
> `client_credentials` grant instead for anything beyond local development.

### `POST /api/clients/{clientId}/api-keys`

Mint a static API key for the client.

**Request** (`application/json`): `{ "name": "..." }` (1–255 chars).

**`201 Created`**

```json
{
  "id": "...",
  "clientId": "...",
  "name": "local dev",
  "prefix": "...",
  "last4": "...",
  "createdAt": 1750000000000,
  "lastUsedAt": null,
  "revokedAt": null,
  "key": "...(plaintext, shown once)"
}
```

Errors: `400`, `401`, `403` (client not in a development environment), `404`.

### `GET /api/clients/{clientId}/api-keys`

List the client's API keys — masked fields only (`prefix` + `last4`, never the
key or its hash). Includes revoked keys (`revokedAt` set).

**`200 OK`**: `{ "apiKeys": [ { "id": "...", "clientId": "...", "name": "...", "prefix": "...", "last4": "...", "createdAt": 0, "lastUsedAt": null, "revokedAt": null } ] }`

Errors: `401`, `404`.

### `DELETE /api/clients/{clientId}/api-keys/{keyId}`

Revoke one API key. Idempotent soft-delete — the row is retained with
`revokedAt` set, and a revoked key never authenticates again.

**`200 OK`** — the revoked key (masked fields, `revokedAt` set).
Errors: `401`, `404` (client or key not found / not owned).

---

## Wallet federation transport (`/oid4vp/response`)

**Flag-gated, off by default.** `POST /oid4vp/response` is registered only when
`WALLET_FEDERATION_ENABLED=true` **and** a `VerifierProfile` is configured for
the deployment; both default off, and with either missing the route does not
exist (404) or fails closed. See the [Status page](/reference/status/) for
where wallet federation stands overall.

**Even when enabled, this endpoint is transport only.** It is the OID4VP 1.0
`direct_post` Response Endpoint: it structurally parses and correlates a
wallet's Authorization Response (`vp_token` + `state`, or `error` + `state`)
against a single-use presentation request. **It performs no signature,
credential, or issuer validation, and authenticates no user.**

**Request** (form-urlencoded): `state` (required), `vp_token`, `error`,
`error_description`.

**`200 OK`** — an empty transport-level acknowledgement (OID4VP 1.0 §8.3)
confirming the response was well-formed and correlated. It does **not** assert
that any credential was verified or any user authenticated.

---

## See also

- [OAuth 2.1 Flow](/integrate/oauth-flow/) — worked flows with `curl`.
- [Hosted UI](/integrate/hosted-ui/) — the login, consent, and resume screens.
- [Agent Authorization](/integrate/agent-authorization/) — the agent-native layer
  (`is_agent`, Token Exchange, scope modes, step-up, audit).
- [Code Examples](/integrate/code-examples/) — runnable Node/TS and browser clients.
- [MCP Quickstart](/integrate/mcp-quickstart/) — protect an MCP server end-to-end.
- [`@qauth-labs/mcp-guard`](https://github.com/qauth-labs/qauth/blob/main/libs/fastify/plugins/mcp-guard/README.md) — the
  resource-server SDK that validates the tokens these endpoints issue.
