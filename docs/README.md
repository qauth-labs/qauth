# QAuth Documentation

QAuth is the open-source, self-hostable **OAuth 2.1 authorization server for MCP
servers and AI agents** (see [ADR-007](./adr/007-mcp-first-positioning.md)). This
is the entry point to the guides; the canonical, always-current API surface is the
interactive **Swagger UI at `/docs`** on any running instance.

> 🎉 **June 2026 — MVP complete and the agent-native authorization layer shipped** (agent client type, RFC 8693 on-behalf-of delegation, scope modes, step-up, per-agent audit), alongside the T3 production-hardening track and the T5 environment-aware authorization posture ([ADR-008](./adr/008-environment-aware-authorization.md)). Start with the [agent-authorization guide](./agent-authorization.md).

## Getting started

| Guide                                         | What it covers                                                                                                                                                                      |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**MCP Quickstart**](./mcp-quickstart.md)     | End-to-end: run QAuth, run a `mcp-guard`-protected MCP resource server, and complete the full discovery → register → `authorization_code` + PKCE → token handshake. **Start here.** |
| [**Docker Guide**](./docker.md)               | Running the stack (auth-server + Postgres + Redis) in development and production; environment variables; CIMD configuration.                                                        |
| [**Observability**](./observability.md)       | Structured logging + secret redaction, request-id tracking, auth-event logging, failed-login lockout, the Prometheus `GET /metrics` endpoint, and recommended Alertmanager rules.   |
| [**Browser Security**](./browser-security.md) | The browser-facing hardening (T3): security headers (nonce-based CSP, HSTS, X-Frame-Options), CSRF double-submit protection, `__Host-` secure cookies, and XSS-safe HTML output.    |

## OAuth 2.1 / OIDC

| Guide                                                                          | What it covers                                                                                                                                                                                      |
| ------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**OAuth 2.1 Flow**](./oauth-flow.md)                                          | Every endpoint with copy-paste `curl`: PKCE generation, `/oauth/authorize`, token exchange, refresh-token rotation, `client_credentials`, introspection, UserInfo, and Dynamic Client Registration. |
| [**ADR-006: OAuth grants & audience**](./adr/006-oauth-grants-and-audience.md) | Why `client_credentials` + `client_secret_basic` and per-client `aud` binding work the way they do.                                                                                                 |

## Agent authorization

| Guide                                               | What it covers                                                                                                                                                                                                                                                                         |
| --------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Agent Authorization**](./agent-authorization.md) | The agent-native layer (ADR-007 §2): the agent client type (`is_agent`), RFC 8693 Token Exchange / on-behalf-of delegation (`act` claim), agent scope modes (ReadOnly / Admin / Exec + the operator-set cap), step-up authentication before dangerous operations, and per-agent audit. |

## API reference

| Guide                                   | What it covers                                                                                                                                                                                                         |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**API Reference**](./api-reference.md) | Hand-written contract for every endpoint: first-party auth (`/auth/*`), OAuth 2.1 (`/oauth/*`), discovery, and client management (`/api/clients`), with request/response shapes, status codes, and the error envelope. |

The authoritative, always-current surface is the live OpenAPI / Swagger UI at
**`/docs`** on the running instance. Also:

- **Resource-server SDK** — [`@qauth-labs/mcp-guard`](../libs/fastify/plugins/mcp-guard/README.md)
  (Protected Resource Metadata, Bearer challenges, JWT/introspection validation).
- The client-management API (`GET/POST/PATCH/DELETE /api/clients`, regenerate-secret)
  is shipped — see [API Reference → Client management](./api-reference.md#client-management-apiclients).

## Code examples

| Guide                                   | What it covers                                                                                                                                                             |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Code Examples**](./code-examples.md) | Copy-paste-ready clients — Node/TS (first-party register→login→protected call; machine `client_credentials`) and browser JS (`authorization_code` + PKCE with Web Crypto). |

- [`memory-mcp` example server](../libs/fastify/plugins/mcp-guard/examples/memory-mcp/server.ts) —
  a runnable, `mcp-guard`-protected resource server (the resource half of the
  quickstart).
- Copy-paste `curl` for every OAuth step in the [OAuth 2.1 Flow](./oauth-flow.md)
  guide.

## Environment-aware authorization

| Guide                                                                                        | What it covers                                                                                                                                                                                          |
| -------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Environment-Aware Authorization**](./environment-authorization.md)                        | Operator/how-to guide: the `environment` (development / staging / production) policy dimension on clients/realms, the profile table, fail-safe defaults, and environment-gated developer API keys (T5). |
| [**ADR-008: Environment-aware authorization**](./adr/008-environment-aware-authorization.md) | The design decision behind the above — fail-safe reasoning, the `resolveEnvironmentPolicy` resolver, and prior-art comparison.                                                                          |

## Architecture & decisions

- [Architecture Decision Records](./adr/README.md) — the design decisions behind
  QAuth, including [ADR-007: MCP-First Positioning](./adr/007-mcp-first-positioning.md)
  and [ADR-008: Environment-aware authorization](./adr/008-environment-aware-authorization.md).
- [MVP-PRD](../MVP-PRD.md) — product requirements, phase breakdown, schema.
- [Milestones](https://github.com/qauth-labs/qauth/milestones) — track status:
  **T0–T3 and T5 complete** (trust floor, MCP productization, agent-native authZ,
  OIDC conformance + hardening, environment-aware authZ); **T4 (wallet federation +
  post-quantum signing) deferred** as the long-term platform.
