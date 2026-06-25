# MCP Quickstart — QAuth as the OAuth 2.1 Authorization Server for an MCP server

This guide takes you from nothing to a **working MCP authorization handshake** on
your machine:

1. Run **QAuth** — the OAuth 2.1 authorization server (AS).
2. Run a **guarded MCP resource server** — the bundled `memory-mcp` example,
   protected by [`@qauth-labs/mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md).
3. Obtain a valid, **audience-bound** access token and call the protected resource.

By the end you will have reproduced the flow from
[ADR-007](./adr/007-mcp-first-positioning.md): an MCP client, given only a server
URL, discovers the authorization server, registers, runs `authorization_code` +
PKCE, and calls the resource with a token QAuth minted and `mcp-guard` validated.

```
  ┌──────────────┐        ┌───────────────────────┐        ┌─────────────────────┐
  │  MCP client  │        │  MCP resource server  │        │  QAuth  (AS)        │
  │ (Claude Code,│        │  memory-mcp + mcp-guard│        │  :3000              │
  │  curl, …)    │        │  :8088                 │        │                     │
  └──────┬───────┘        └───────────┬───────────┘        └──────────┬──────────┘
         │  GET /mcp/memory (no token)│                               │
         │ ──────────────────────────▶│                               │
         │  401 WWW-Authenticate:     │                               │
         │  Bearer resource_metadata= │                               │
         │ ◀──────────────────────────│                               │
         │  GET /.well-known/oauth-protected-resource                 │
         │ ──────────────────────────▶│                               │
         │  { authorization_servers: ["http://localhost:3000"], … }   │
         │ ◀──────────────────────────│                               │
         │  discover AS, register, authorization_code + PKCE          │
         │ ───────────────────────────────────────────────────────-─▶│
         │  access_token (aud = http://localhost:8088, scope mcp:read)│
         │ ◀───────────────────────────────────────────────────────-─│
         │  GET /mcp/memory   Authorization: Bearer <token>           │
         │ ──────────────────────────▶│  (mcp-guard verifies sig,     │
         │  200 ✅                     │   iss, aud, scope)            │
         │ ◀──────────────────────────│                               │
```

> **Scope of the bundled example.** `memory-mcp` is a minimal Fastify server that
> demonstrates the **authorization** half — the 401 challenge, Protected Resource
> Metadata, and token validation. It exposes plain HTTP routes (`/mcp/memory`)
> rather than the full MCP JSON-RPC transport, so you verify it with `curl`. To
> drive it from a real MCP client, wrap your own MCP server with `mcp-guard` the
> same way (see [Step 3](#step-3--connect-an-mcp-client)); the OAuth handshake is
> identical.

---

## Prerequisites

- **Docker** 23.0+ and **Docker Compose** 2.0+ (BuildKit on by default)
- **OpenSSL** (to generate the JWT signing key)
- **Node.js 20+** with `pnpm` and `tsx` (to run the example resource server)
- `curl` and `jq` for the walkthrough

---

## Step 1 — Run QAuth (the authorization server)

QAuth signs tokens with **EdDSA (Ed25519)**. Generate a key pair and point the
stack at it.

```bash
git clone https://github.com/qauth-labs/qauth.git
cd qauth

# 1. Generate the EdDSA signing key pair
openssl genpkey -algorithm Ed25519 -out private.pem
openssl pkey -in private.pem -pubout -out public.pem

# 2. Create your .env from the example
cp .env.docker.example .env
```

Edit `.env` and set the keys (include the `BEGIN/END` lines, wrapped in double
quotes) and the issuer:

```dotenv
DB_PASSWORD=change_me

JWT_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
...contents of private.pem...
-----END PRIVATE KEY-----"

JWT_PUBLIC_KEY="-----BEGIN PUBLIC KEY-----
...contents of public.pem...
-----END PUBLIC KEY-----"

JWT_ISSUER=http://localhost:3000

# Let dynamically-registered MCP clients request MCP scopes.
# The default allows only OIDC-core scopes (openid profile email offline_access),
# so an MCP client's `mcp:read`/`mcp:write` request would otherwise be denied.
DEFAULT_DYNAMIC_REGISTRATION_SCOPES=openid profile email offline_access mcp:read mcp:write
```

Start the stack (auth-server + PostgreSQL 18 + Redis 7 + migrations) and verify:

```bash
docker compose up -d
curl -s http://localhost:3000/health | jq
```

```json
{ "status": "ok", "services": { "database": "connected", "redis": "connected" } }
```

Confirm the discovery document advertises the endpoints an MCP client needs:

```bash
curl -s http://localhost:3000/.well-known/oauth-authorization-server | jq
```

```jsonc
{
  "issuer": "http://localhost:3000",
  "authorization_endpoint": "http://localhost:3000/oauth/authorize",
  "token_endpoint": "http://localhost:3000/oauth/token",
  "registration_endpoint": "http://localhost:3000/oauth/register",
  "jwks_uri": "http://localhost:3000/.well-known/jwks.json",
  "code_challenge_methods_supported": ["S256"],
  "resource_indicators_supported": true,
  "client_id_metadata_document_supported": true, // CIMD on by default
}
```

> Interactive API docs (Swagger UI) are served at `http://localhost:3000/docs`.
> See the [Docker guide](./docker.md) for development mode, CIMD settings, and
> production considerations.

---

## Step 2 — Run a guarded MCP resource server

The repo ships a runnable example — a tiny in-memory store protected by
`mcp-guard` in local-JWT validation mode (it verifies tokens against QAuth's
JWKS, no per-request call to the AS).

```bash
cd libs/fastify/plugins/mcp-guard

QAUTH_ISSUER=http://localhost:3000 \
MCP_RESOURCE=http://localhost:8088 \
npx tsx examples/memory-mcp/server.ts
```

`MCP_RESOURCE` is this server's canonical URL — the `aud` value every accepted
token must carry (RFC 8707). In a separate shell, confirm the two unauthenticated
behaviours an MCP client relies on:

```bash
# Protected Resource Metadata (RFC 9728) — points clients at the AS:
curl -s http://localhost:8088/.well-known/oauth-protected-resource | jq
# → { "resource": "http://localhost:8088",
#     "authorization_servers": ["http://localhost:3000"], … }

# A protected call with no token → 401 + the Bearer challenge:
curl -i http://localhost:8088/mcp/memory
# → HTTP/1.1 401 Unauthorized
#   WWW-Authenticate: Bearer resource_metadata="http://localhost:8088/.well-known/oauth-protected-resource"
```

This is the trigger that starts the whole handshake: a 401 with a pointer to the
metadata document.

---

## Step 3 — Connect an MCP client

### Option A — A real MCP client (e.g. Claude Code)

Wrap your **actual** MCP server with `mcp-guard` exactly as the example does
(register the plugin, guard routes with `app.requireBearer` /
`app.requireScopes(...)`), then add it to your MCP client as an HTTP server:

```bash
# Exact syntax varies by client/version — check `claude mcp add --help`.
claude mcp add --transport http memory http://localhost:8088/mcp
```

On first use the client will:

1. call the server, get the **401** + `WWW-Authenticate` challenge,
2. fetch **Protected Resource Metadata** and discover QAuth,
3. **register** itself — via Client ID Metadata Documents (CIMD) or Dynamic
   Client Registration (see [below](#client-registration-cimd-vs-dcr)),
4. run **`authorization_code` + PKCE**, opening a browser for **login + consent**
   at QAuth (you'll register/sign in and approve the `mcp:read` / `mcp:write`
   scopes),
5. retry the call with the issued token — `mcp-guard` validates it and returns `200`.

Because the client passes the resource URL as the RFC 8707 `resource` parameter,
the token's `aud` is bound to `http://localhost:8088` and is useless at any other
resource server.

### Option B — Verify the handshake with curl (no browser)

To prove the token half end-to-end without an interactive client, mint a
**`client_credentials`** (machine) token. This needs a client whose `scopes` and
`audience` are set explicitly, which the seed script provisions.

```bash
# The seed script targets an existing realm. The default realm ("master") is
# created lazily on first auth request, so warm it up with one throwaway
# Dynamic Client Registration call (open mode — no token required):
curl -s -X POST http://localhost:3000/oauth/register \
  -H 'Content-Type: application/json' \
  -d '{"client_name":"warmup","grant_types":["authorization_code"],"redirect_uris":["http://localhost/cb"],"token_endpoint_auth_method":"none"}' \
  >/dev/null

# Provision a machine client bound to the example's resource URL:
cat > /tmp/mcp-demo-clients.json <<'JSON'
{
  "realm": "master",
  "clients": [
    {
      "client_id": "memory-mcp-demo",
      "name": "memory-mcp demo (client_credentials)",
      "grant_types": ["client_credentials"],
      "scopes": ["mcp:read", "mcp:write"],
      "audience": ["http://localhost:8088"],
      "token_endpoint_auth_method": "client_secret_basic"
    }
  ]
}
JSON

# Seed it (prints the generated client_secret once — capture it):
DATABASE_URL="postgresql://qauth:${DB_PASSWORD}@localhost:5432/qauth" \
  pnpm nx run infra-db:db:seed-oauth-clients -- --manifest=/tmp/mcp-demo-clients.json
```

Exchange the credentials for an audience-bound token, then call the resource:

```bash
CLIENT_ID=memory-mcp-demo
CLIENT_SECRET=<paste the secret printed above>

ACCESS_TOKEN=$(curl -s -X POST http://localhost:3000/oauth/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials' \
  -d 'scope=mcp:read' \
  -d 'resource=http://localhost:8088' | jq -r .access_token)

# Call the protected resource — mcp-guard verifies signature, issuer, aud, scope:
curl -s http://localhost:8088/mcp/memory \
  -H "Authorization: Bearer $ACCESS_TOKEN" | jq
# → { "subject": "memory-mcp-demo", "client": "memory-mcp-demo", "items": {} }  ✅
```

A token carrying only `mcp:read` against the write route returns a **step-up**
challenge — exactly what drives incremental consent in a real client:

```bash
curl -i -X PUT http://localhost:8088/mcp/memory/greeting \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"value":"hi"}'
# → HTTP/1.1 403 Forbidden
#   WWW-Authenticate: Bearer error="insufficient_scope", scope="mcp:read mcp:write",
#                     resource_metadata="http://localhost:8088/.well-known/oauth-protected-resource"
```

(Request `scope=mcp:read mcp:write` at the token endpoint to get a token that
satisfies both routes.)

---

## Client registration: CIMD vs DCR

QAuth supports two ways for an MCP client to obtain a `client_id`. Both are
advertised in discovery.

| Mechanism                                                | When QAuth uses it                                                | Best for                                                                                                                                                                                 |
| -------------------------------------------------------- | ----------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **CIMD** — Client ID Metadata Documents (MCP 2025-11-25) | `client_id` is an **HTTPS URL** resolving to a metadata document  | Production clients with a stable, public metadata URL. No registration record is persisted (no open-DCR abuse surface).                                                                  |
| **DCR** — Dynamic Client Registration (RFC 7591)         | `POST /oauth/register`, **open mode** (no `initial_access_token`) | Local development and clients without a public URL. Scopes are **capped to the realm allowlist** (`DEFAULT_DYNAMIC_REGISTRATION_SCOPES`) — this is why Step 1 adds `mcp:read mcp:write`. |

- **CIMD** is on by default (`CIMD_ENABLED=true`). It requires the client's
  `client_id` URL to be fetchable over HTTPS; the AS validates it (URL ==
  `client_id`, redirect-URI checks, SSRF guards, size/TTL limits). For purely
  local testing over `http://localhost`, CIMD is impractical — use DCR.
- **DCR** open mode is rate-limited (3 registrations/hour/IP by default). Tighten
  or gate it for any internet-facing deployment. See
  [ADR-007 §1](./adr/007-mcp-first-positioning.md) and the
  [Docker guide CIMD section](./docker.md#client-id-metadata-documents-cimd).

---

## How tokens stay scoped to one resource

The no-passthrough guarantee rests on **audience binding** (RFC 8707):

- The client sends `resource=<MCP server URL>` on authorize/token requests.
- QAuth mints the access token with `aud` set to that resource and refuses to
  widen it on refresh.
- `mcp-guard` rejects any token whose `aud` does not include its own `resource`,
  and never forwards the inbound token upstream.

A token minted for resource A therefore cannot be replayed against resource B,
even if both trust the same QAuth instance.

---

## Troubleshooting

| Symptom                           | Likely cause / fix                                                                                                                                                                                       |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `401` even with a token           | Token `aud` ≠ the server's `MCP_RESOURCE`. Ensure the `resource` you requested matches `MCP_RESOURCE` exactly.                                                                                           |
| `invalid_scope` at `/oauth/token` | The client's `scopes` (machine client) or the realm allowlist (DCR client) doesn't include the requested scope. Re-check Step 1's `DEFAULT_DYNAMIC_REGISTRATION_SCOPES` or the seeded client's `scopes`. |
| Seed script: realm not found      | The `master` realm hasn't been created yet — run the warm-up DCR call in Step 3 Option B first.                                                                                                          |
| `mcp-guard` can't fetch JWKS      | `QAUTH_ISSUER` must be reachable from the resource server and serve `/.well-known/jwks.json`.                                                                                                            |
| Port already in use               | Override `PORT` for the example, or remap `3000`/`5432`/`6379` in `docker-compose.yml`.                                                                                                                  |

---

## Next steps

- [OAuth 2.1 Flow](./oauth-flow.md) — the `authorization_code` + PKCE flow in
  detail, with copy-paste `curl` for every step (build your own client).
- [Agent Authorization](./agent-authorization.md) — when an **AI agent** acts on
  behalf of a user: the `is_agent` client type, RFC 8693 token-exchange
  delegation, agent scope modes, and step-up before dangerous operations.
- [`@qauth-labs/mcp-guard` README](../libs/fastify/plugins/mcp-guard/README.md) —
  full configuration, `introspection` mode, and the framework-agnostic core.
- [ADR-007: MCP-First Positioning](./adr/007-mcp-first-positioning.md) — why this
  is QAuth's near-term product identity.
- [Docker guide](./docker.md) — development mode, CIMD configuration, production.
