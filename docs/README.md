# QAuth Documentation

QAuth is the open-source, self-hostable **OAuth 2.1 authorization server for MCP
servers and AI agents** (see [ADR-007](./adr/007-mcp-first-positioning.md)). This
is the entry point to the guides; the canonical, always-current API surface is the
interactive **Swagger UI at `/docs`** on any running instance.

## Getting started

| Guide                                     | What it covers                                                                                                                                                                      |
| ----------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**MCP Quickstart**](./mcp-quickstart.md) | End-to-end: run QAuth, run a `mcp-guard`-protected MCP resource server, and complete the full discovery → register → `authorization_code` + PKCE → token handshake. **Start here.** |
| [**Docker Guide**](./docker.md)           | Running the stack (auth-server + Postgres + Redis) in development and production; environment variables; CIMD configuration.                                                        |

## OAuth 2.1 / OIDC

| Guide                                                                          | What it covers                                                                                                                                                                                      |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**OAuth 2.1 Flow**](./oauth-flow.md)                                          | Every endpoint with copy-paste `curl`: PKCE generation, `/oauth/authorize`, token exchange, refresh-token rotation, `client_credentials`, introspection, UserInfo, and Dynamic Client Registration. |
| [**ADR-006: OAuth grants & audience**](./adr/006-oauth-grants-and-audience.md) | Why `client_credentials` + `client_secret_basic` and per-client `aud` binding work the way they do.                                                                                                 |

## API reference

QAuth serves a live OpenAPI / Swagger UI at **`/docs`** on the running
instance — that is the authoritative, versioned reference for request/response
shapes and error codes.

- **OAuth / OIDC endpoints** — documented with examples in
  [OAuth 2.1 Flow](./oauth-flow.md).
- **Resource-server SDK** — [`@qauth-labs/mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md)
  (Protected Resource Metadata, Bearer challenges, JWT/introspection validation).
- **Auth & client-management endpoints** — a standalone, hand-written reference
  ([issue #99](https://github.com/qauth-labs/qauth/issues/99)) is in progress; the
  client-management (`/api/clients`) section lands with the T2 milestone.

## Code examples

- [`memory-mcp` example server](../libs/fastify/plugins/mcp-guard/examples/memory-mcp/server.ts) —
  a runnable, `mcp-guard`-protected resource server (the resource half of the
  quickstart).
- Copy-paste `curl` for every OAuth step in the [OAuth 2.1 Flow](./oauth-flow.md)
  guide.
- A Node/TypeScript client walkthrough ([issue #100](https://github.com/qauth-labs/qauth/issues/100))
  is planned.

## Architecture & decisions

- [Architecture Decision Records](./adr/README.md) — the design decisions behind
  QAuth, including [ADR-007: MCP-First Positioning](./adr/007-mcp-first-positioning.md).
- [MVP-PRD](../MVP-PRD.md) — product requirements, phase breakdown, schema.
- [Milestones](https://github.com/qauth-labs/qauth/milestones) — current track
  status (T0–T4).
