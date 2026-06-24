# @qauth-labs/mcp-guard

The resource-server (RS) side SDK for protecting an **MCP server** with a
self-hosted **[QAuth](../../../../README.md)** OAuth 2.1 authorization server.

Drop it into an MCP server and you get spec-correct OAuth in minutes:

- **RFC 9728** Protected Resource Metadata at
  `/.well-known/oauth-protected-resource[/<path>]`
- **RFC 6750 §3** `401` / `403` `WWW-Authenticate: Bearer` challenges, with the
  `resource_metadata` pointer (and the well-known doc as the fallback per MCP
  2025-11-25)
- Bearer-token validation in two modes — local **JWT** verification against the
  QAuth JWKS, or **RFC 7662** introspection
- **No token passthrough**: tokens not audience-bound to this resource
  (**RFC 8707**) are rejected, and the inbound token is never forwarded upstream
- **Step-up** `403 insufficient_scope` scope challenges for incremental consent

It ships both a **Fastify 5 plugin** and a **framework-agnostic core**
(`McpGuard`) for non-Fastify hosts.

> Targets the MCP Authorization profile **revision 2025-11-25** and QAuth's AS
> contract (JWKS at `/.well-known/jwks.json`, discovery at
> `/.well-known/oauth-authorization-server`, introspection at
> `/oauth/introspect`). See [ADR-007](../../../../docs/adr/007-mcp-first-positioning.md).

## Install

```bash
pnpm add @qauth-labs/mcp-guard
# peer deps: fastify@5, jose@6
```

## Quick start (Fastify)

```ts
import Fastify from 'fastify';
import { mcpGuardPlugin } from '@qauth-labs/mcp-guard';

const app = Fastify();

await app.register(mcpGuardPlugin, {
  // This resource's canonical URL — the `aud` every accepted token must carry.
  resource: 'https://memory.mcp.example.com',
  // Your QAuth instance (the issuer identifier).
  authorizationServer: 'https://auth.example.com',
  // Default scopes required for any protected route.
  requiredScopes: ['mcp:read'],
  // 'jwt' (default, offline) | 'introspection' (RFC 7662, online).
  validationMode: 'jwt',
});

// Require a valid, audience-bound bearer carrying the default scopes:
app.get('/mcp/memory', { preHandler: app.requireBearer }, async (req) => {
  return { subject: req.tokenClaims?.sub };
});

// Step-up: this route additionally requires `mcp:write`. A token missing it
// gets a 403 insufficient_scope challenge advertising the full required set.
app.put('/mcp/memory/:key', { preHandler: app.requireScopes('mcp:write') }, async (req) => {
  return { ok: true };
});
```

Registering the plugin automatically:

1. serves the RFC 9728 metadata document (`GET /.well-known/oauth-protected-resource`,
   plus the nested path for a path-bearing `resource`),
2. decorates the instance with `mcpGuard`, `requireBearer`, and `requireScopes(...)`,
3. converts guard failures into the correct Bearer challenge responses.

The validated claims are available on `request.tokenClaims`
(`{ sub, clientId, scopes, audience, issuer, expiresAt, issuedAt, raw }`).

## The handshake (what an MCP client sees)

```
client → GET /mcp/memory                         (no token)
server → 401  WWW-Authenticate: Bearer
              resource_metadata="https://…/.well-known/oauth-protected-resource"
client → GET /.well-known/oauth-protected-resource
server → 200  { resource, authorization_servers: ["https://auth.example.com"], … }
client → (discovers AS, runs authorization_code + PKCE against QAuth, gets a
          token with aud=https://memory.mcp.example.com)
client → GET /mcp/memory   Authorization: Bearer <token>
server → 200  ✅  (mcp-guard verified signature, issuer, audience, scopes)
```

## Validation modes

### `jwt` (default, recommended)

Verifies the bearer locally against the QAuth JWKS using `jose`
(`createRemoteJWKSet`). Checks the EdDSA signature, `iss`, `exp`, and that
`aud` contains this resource. No per-request call to the AS. The JWKS is cached
in-process; control freshness with `jwksCacheTtlMs` (default 5 min) so rotated
AS keys are picked up automatically.

### `introspection` (RFC 7662)

Calls the QAuth introspection endpoint for every request — use for opaque
tokens or near-real-time revocation. Requires confidential client credentials
(RFC 7662 mandates client authentication):

```ts
await app.register(mcpGuardPlugin, {
  resource: 'https://memory.mcp.example.com',
  authorizationServer: 'https://auth.example.com',
  validationMode: 'introspection',
  introspectionClient: {
    clientId: process.env.INTROSPECT_CLIENT_ID!,
    clientSecret: process.env.INTROSPECT_CLIENT_SECRET!,
  },
});
```

Even though QAuth only returns `active: true` to an audience-authoritative
introspection client, `mcp-guard` re-checks `aud` locally as defence-in-depth,
so the no-passthrough guarantee never depends solely on AS-side configuration.

## Configuration

| Option                  | Type                         | Default                                        | Notes                                                   |
| ----------------------- | ---------------------------- | ---------------------------------------------- | ------------------------------------------------------- |
| `resource`              | `string` (required)          | —                                              | Resource identifier; `aud` tokens must carry (RFC 8707) |
| `authorizationServer`   | `string` (required)          | —                                              | QAuth issuer identifier                                 |
| `requiredScopes`        | `string[]`                   | `[]`                                           | Default scopes for any protected route                  |
| `validationMode`        | `'jwt' \| 'introspection'`   | `'jwt'`                                        | Token-validation strategy                               |
| `jwksUri`               | `string`                     | `${authorizationServer}/.well-known/jwks.json` | JWT mode                                                |
| `jwksCacheTtlMs`        | `number`                     | `300000`                                       | JWKS cache/cooldown (JWT mode)                          |
| `introspectionEndpoint` | `string`                     | `${authorizationServer}/oauth/introspect`      | Introspection mode                                      |
| `introspectionClient`   | `{ clientId, clientSecret }` | —                                              | **Required** in introspection mode                      |
| `allowedAlgorithms`     | `string[]`                   | `['EdDSA']`                                    | Pinned to defend against alg-confusion (JWT mode)       |
| `metadataCacheControl`  | `string`                     | `public, max-age=3600`                         | `Cache-Control` for the PRM document                    |
| `fetch`                 | `FetchLike`                  | global `fetch`                                 | Injectable (tests / SSRF-guarded client)                |

## Framework-agnostic core

```ts
import { McpGuard, McpGuardError } from '@qauth-labs/mcp-guard';

const guard = new McpGuard({
  resource: 'https://memory.mcp.example.com',
  authorizationServer: 'https://auth.example.com',
  requiredScopes: ['mcp:read'],
});

try {
  const claims = await guard.authenticate(req.headers.authorization, ['mcp:write']);
  // claims.sub, claims.scopes, claims.audience, …
} catch (err) {
  if (err instanceof McpGuardError) {
    res.statusCode = err.statusCode; // 401 | 403
    res.setHeader('WWW-Authenticate', guard.challengeHeader(err));
    res.end();
  }
}
```

- `guard.getProtectedResourceMetadata()` — the RFC 9728 document to serve.
- `guard.getMetadataPath()` / `getMetadataUrl()` — well-known path / absolute URL.
- `guard.assertScopes(claims, ['mcp:write'])` — mid-handler step-up check.

## Security model

- **Audience binding (RFC 8707).** Both validators reject any token whose `aud`
  does not include `resource`. This is the no-passthrough control: a token
  minted for another resource cannot be replayed here.
- **No upstream forwarding.** The core only validates and returns _claims_; it
  never returns the raw token to a call site or forwards it to upstream APIs.
- **Algorithm pinning.** JWT mode accepts `EdDSA` only by default, closing
  algorithm-confusion attacks.
- **Fail closed.** Transport errors, non-2xx introspection responses, malformed
  tokens, and unknown signing keys all fail validation. Error reasons are short
  and non-sensitive; **the token is never echoed** in a challenge or a log.

## Runnable example

A minimal MCP-style memory server is in [`examples/memory-mcp/server.ts`](./examples/memory-mcp/server.ts).
It is the RS half of the Claude Code → QAuth → MCP quickstart:

```bash
QAUTH_ISSUER=http://localhost:3000 \
MCP_RESOURCE=http://localhost:8088 \
npx tsx examples/memory-mcp/server.ts
```

## Standards

RFC 9728 (Protected Resource Metadata) · RFC 8707 (Resource Indicators) ·
RFC 7662 (Token Introspection) · RFC 6750 §3 (Bearer challenges) ·
RFC 8414 (AS Metadata) · MCP Authorization 2025-11-25.

## Testing

```bash
pnpm nx test mcp-guard
pnpm nx build mcp-guard
```
