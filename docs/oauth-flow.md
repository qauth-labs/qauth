# OAuth 2.1 Flow

This page documents QAuth's OAuth 2.1 / OIDC endpoints with copy-paste `curl`
for every step, so you can implement a client by hand. If your goal is to wire
QAuth to an **MCP server**, start with the [MCP Quickstart](./mcp-quickstart.md) —
this page is the lower-level reference it builds on.

**Conventions used below**

- Base URL / issuer: `http://localhost:3000` (your `JWT_ISSUER`).
- Tokens are **EdDSA (Ed25519)** signed JWTs; verify them against
  `GET /.well-known/jwks.json`.
- PKCE is **required** and only `S256` is supported.
- Request bodies to `/oauth/token` and `/oauth/introspect` are
  `application/x-www-form-urlencoded` (RFC 6749 §3.2, RFC 7662 §2.1).

Standards: RFC 6749 (OAuth 2.0) · OAuth 2.1 draft · RFC 7636 (PKCE) · RFC 8707
(Resource Indicators) · RFC 7662 (Introspection) · RFC 8414 (AS Metadata) ·
OIDC Core / Discovery 1.0 · RFC 9700 (OAuth 2.0 Security BCP).

---

## Endpoints at a glance

| Endpoint                                  | Method | Purpose                                      |
| ----------------------------------------- | ------ | -------------------------------------------- |
| `/.well-known/oauth-authorization-server` | GET    | AS metadata (RFC 8414)                       |
| `/.well-known/openid-configuration`       | GET    | OIDC discovery (superset)                    |
| `/.well-known/jwks.json`                  | GET    | Public signing keys (RFC 7517)               |
| `/oauth/authorize`                        | GET    | Start `authorization_code` + PKCE (browser)  |
| `/oauth/token`                            | POST   | Exchange code / refresh / client credentials |
| `/oauth/introspect`                       | POST   | Token introspection (RFC 7662)               |
| `/oauth/userinfo`                         | GET    | OIDC UserInfo (Bearer)                       |
| `/oauth/register`                         | POST   | Dynamic Client Registration (RFC 7591, open) |

Discover these programmatically instead of hard-coding paths:

```bash
curl -s http://localhost:3000/.well-known/oauth-authorization-server | jq
```

---

## Grant types

| Grant                         | Subject (`sub`) | Refresh token?       | Use case                                   |
| ----------------------------- | --------------- | -------------------- | ------------------------------------------ |
| `authorization_code` (+ PKCE) | the end user    | yes                  | Apps acting **on behalf of a user**        |
| `refresh_token`               | the end user    | yes (rotated)        | Renew an access token without re-prompting |
| `client_credentials`          | the `client_id` | no (RFC 6749 §4.4.3) | **Machine-to-machine**, no user            |

`response_type` is `code` only. There is no implicit or password grant
(removed in OAuth 2.1).

---

## Authorization Code + PKCE (user context)

### 0. Prerequisites — a client

You need a registered client with the `authorization_code` grant, a registered
`redirect_uri`, and the scopes you want in its allowlist. A **public** client
(SPA / native / CLI) uses `token_endpoint_auth_method: none` and authenticates
purely with PKCE — no secret. Register one with
[Dynamic Client Registration](#dynamic-client-registration-rfc-7591):

```bash
curl -s -X POST http://localhost:3000/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{
    "client_name": "My App",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "redirect_uris": ["http://localhost:5173/callback"],
    "token_endpoint_auth_method": "none"
  }' | jq
# → { "client_id": "…", "token_endpoint_auth_method": "none", … }
```

> **Scopes are deny-by-default.** The authorize endpoint only grants scopes that
> are in the client's allowlist. DCR-registered clients are capped to the realm
> allowlist (`DEFAULT_DYNAMIC_REGISTRATION_SCOPES`); set that env var to include
> any non-OIDC scopes (e.g. `mcp:read`) you intend to request.

### 1. Generate a PKCE verifier and challenge (RFC 7636)

```bash
# code_verifier: 43–128 chars from [A-Za-z0-9._~-]
code_verifier=$(openssl rand -base64 96 | tr -d '\n=+/' | cut -c1-64)

# code_challenge = BASE64URL(SHA256(code_verifier))
code_challenge=$(printf '%s' "$code_verifier" \
  | openssl dgst -binary -sha256 \
  | openssl base64 | tr '+/' '-_' | tr -d '=\n')

echo "verifier=$code_verifier"
echo "challenge=$code_challenge"
```

Keep `code_verifier` secret and in memory; you'll send it at the token step.

### 2. Redirect the user to `/oauth/authorize`

Open this URL **in a browser** (the user authenticates and consents at QAuth):

```
http://localhost:3000/oauth/authorize
  ?response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=http://localhost:5173/callback
  &code_challenge=CODE_CHALLENGE
  &code_challenge_method=S256
  &scope=openid%20profile%20email
  &state=RANDOM_OPAQUE_VALUE
  &resource=http://localhost:8088
```

| Parameter               | Required    | Notes                                                           |
| ----------------------- | ----------- | --------------------------------------------------------------- |
| `response_type`         | yes         | Must be `code`.                                                 |
| `client_id`             | yes         | Your client.                                                    |
| `redirect_uri`          | yes         | Must exactly match a registered URI.                            |
| `code_challenge`        | yes         | From step 1.                                                    |
| `code_challenge_method` | yes         | Must be `S256`.                                                 |
| `scope`                 | no          | Space-separated; filtered to the client's allowlist.            |
| `state`                 | recommended | Opaque CSRF value; echoed back verbatim.                        |
| `nonce`                 | OIDC        | Bound into the ID token when issued.                            |
| `resource`              | no          | RFC 8707 target(s); binds the token `aud`. Repeat for multiple. |

QAuth flow: if there's no active session it shows the **login** page; then a
**consent** screen for the requested scopes (skipped if a prior consent already
covers them). On approval it redirects:

```
http://localhost:5173/callback?code=AUTH_CODE&state=RANDOM_OPAQUE_VALUE
```

Verify `state` matches what you sent before proceeding.

### 3. Exchange the code for tokens

```bash
curl -s -X POST http://localhost:3000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=authorization_code \
  -d code=AUTH_CODE \
  -d redirect_uri=http://localhost:5173/callback \
  -d client_id=YOUR_CLIENT_ID \
  -d code_verifier=$code_verifier \
  -d resource=http://localhost:8088 | jq
```

```json
{
  "access_token": "eyJ…",
  "refresh_token": "a1b2…(64 hex)",
  "expires_in": 900,
  "token_type": "Bearer",
  "scope": "openid profile email"
}
```

Notes:

- **Confidential** clients additionally authenticate, either with HTTP Basic
  (`-u "CLIENT_ID:CLIENT_SECRET"`, `client_secret_basic`) or by adding
  `-d client_secret=…` (`client_secret_post`). Public clients send neither.
- The authorization code is single-use and short-lived; the same
  `redirect_uri` and a PKCE-matching `code_verifier` are mandatory.
- `resource` here must be a **subset** of the resource set bound at authorize
  time, or you get `invalid_target`. Omit it to inherit the code's binding.

### 4. Call a protected resource

```bash
curl -s http://localhost:8088/mcp/memory \
  -H "Authorization: Bearer ACCESS_TOKEN" | jq
```

A resource server (e.g. one using [`mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md))
verifies the signature against the JWKS and checks `iss`, `exp`, `aud`, and scope.

---

## Refresh Token (rotation)

Renew an access token without re-prompting the user. QAuth **rotates** the
refresh token on every use and detects replay (RFC 9700 §2.2.2): reusing a
already-rotated token revokes the entire token family.

```bash
curl -s -X POST http://localhost:3000/oauth/token \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=refresh_token \
  -d refresh_token=CURRENT_REFRESH_TOKEN \
  -d client_id=YOUR_CLIENT_ID | jq
```

- The response contains a **new** `refresh_token` — store it and discard the old.
- `scope` may be passed to **down-scope** only; requesting a scope not in the
  original set returns `invalid_scope`. Omit it to keep the original scopes.
- `resource` may **narrow** the audience but never widen it beyond the set bound
  to the refresh token.
- Confidential clients authenticate as in step 3; public clients send only
  `client_id` (ownership is enforced by refresh-token binding).

---

## Client Credentials (machine-to-machine)

No user, no browser. The token's `sub` is the `client_id` and no refresh token
is issued.

```bash
curl -s -X POST http://localhost:3000/oauth/token \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d grant_type=client_credentials \
  -d scope=mcp:read \
  -d resource=http://localhost:8088 | jq
```

- The client must have the `client_credentials` grant and the requested scopes
  in its `scopes` allowlist. **At least one scope is required** (a scopeless
  machine token is rejected per RFC 9700).
- `resource` must fall within the client's configured `audience` (or defaults to
  the `client_id`); it sets the token `aud`.
- Provision such clients with the seed script (it lets you set `scopes` and
  `audience` explicitly) — see the
  [MCP Quickstart, Option B](./mcp-quickstart.md#option-b--verify-the-handshake-with-curl-no-browser).

---

## Token Introspection (RFC 7662)

Resource servers can validate opaque or near-real-time-revocable tokens by
asking the AS. Requires **confidential** client authentication.

```bash
curl -s -X POST http://localhost:3000/oauth/introspect \
  -u "CLIENT_ID:CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d token=ACCESS_TOKEN | jq
```

```json
{
  "active": true,
  "sub": "…",
  "client_id": "…",
  "scope": "openid profile email",
  "aud": "http://localhost:8088",
  "iss": "http://localhost:3000",
  "exp": 1750000000,
  "iat": 1749999100,
  "token_type": "Bearer"
}
```

An inactive, expired, unknown, or wrong-audience token returns
`{ "active": false }` with no other fields. For most resource servers, **local
JWT verification against the JWKS is preferred** (no per-request round-trip);
use introspection when you need immediate revocation.

---

## UserInfo (OIDC)

Return the authenticated end user's claims for a user-context access token:

```bash
curl -s http://localhost:3000/oauth/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN" | jq
# → { "sub": "…", "email": "…", "email_verified": true }
```

---

## Dynamic Client Registration (RFC 7591)

`POST /oauth/register` is **open** (no `initial_access_token`) and rate-limited.
See the example in [step 0](#0-prerequisites--a-client). Key fields:

| Field                        | Notes                                                                  |
| ---------------------------- | ---------------------------------------------------------------------- |
| `redirect_uris`              | Required for `authorization_code`.                                     |
| `grant_types`                | Subset of `authorization_code`, `refresh_token`, `client_credentials`. |
| `token_endpoint_auth_method` | `none` (public/PKCE), `client_secret_basic`, or `client_secret_post`.  |
| `scope`                      | Space-separated; **capped to the realm allowlist**.                    |

For MCP clients, **CIMD** (an HTTPS-URL `client_id`) is the recommended
alternative to DCR — see the [MCP Quickstart](./mcp-quickstart.md#client-registration-cimd-vs-dcr).

---

## Errors

QAuth returns standard OAuth error codes (RFC 6749 §5.2):

| Code                     | Meaning                                                                    |
| ------------------------ | -------------------------------------------------------------------------- |
| `invalid_request`        | Missing/malformed parameter.                                               |
| `invalid_client`         | Client authentication failed or client unknown.                            |
| `invalid_grant`          | Bad/expired code, bad PKCE verifier, or invalid/replayed refresh token.    |
| `unauthorized_client`    | Client not allowed to use this grant.                                      |
| `invalid_scope`          | Requested scope outside the allowlist (or empty for `client_credentials`). |
| `invalid_target`         | RFC 8707 `resource` outside the grant's bound audience.                    |
| `unsupported_grant_type` | Unknown `grant_type`.                                                      |

---

## See also

- [MCP Quickstart](./mcp-quickstart.md) — end-to-end QAuth → MCP handshake.
- [`@qauth-labs/mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md) —
  resource-server SDK that validates these tokens.
- [ADR-006: OAuth grants and audience](./adr/006-oauth-grants-and-audience.md).
