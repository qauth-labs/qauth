# ADR-007: MCP-First Positioning — OAuth 2.1 Authorization Server for MCP / AI Agents

**Status:** Accepted
**Date:** 2026-06-23
**Authors:** QAuth Team

## Context

The OAuth 2.1 work integrated in PR #156 (`integration/oauth-mcp-stack`) was built, in its own words, for _"first-class MCP / third-party client support."_ It delivered, together and in one release:

- Authorization Server Metadata — `/.well-known/oauth-authorization-server` (RFC 8414)
- OIDC discovery + JWKS — `/.well-known/openid-configuration`, `/.well-known/jwks.json`
- Dynamic Client Registration — `POST /oauth/register` (RFC 7591, open mode)
- Resource Indicators — `resource`-bound, audience-scoped tokens across authorize → code → token → refresh (RFC 8707)
- Public-client (`token_endpoint_auth_method=none`) `authorization_code` + PKCE (PR #159)
- A browser consent screen with session cookies and a revocation surface

This was validated end-to-end: **Claude Code**, configured with only a server URL, drove the full `on-401 → discovery → dynamic registration → authorization_code + PKCE → consent → token` handshake against a live `memory-mcp` server deployed at `qauth.naqshi.net`.

Two facts make this strategically significant:

1. **It was off-roadmap.** "MCP" appears nowhere in the MVP-PRD or README. The capability maps to the PRD's vaguest, furthest-out item — "Phase 9: Agent Authentication & Authorization (TBD)" — whose _protocol foundation_ we have now shipped years ahead of plan. The authorization-server side of the MCP authorization profile is essentially complete and live-tested.

2. **The originally-pitched differentiators are still paper.** Wallet federation ([ADR-004](./004-wallet-agnostic-federation.md)), post-quantum hybrid signing ([ADR-005](./005-pqc-hybrid-signing.md)), and the identifier-abstraction model ([ADR-002](./002-identifier-abstraction.md) / [ADR-003](./003-credential-provider-interface.md)) remain accepted designs with no implementing code. All of Phase 4/5 is gated on the ADR-002 schema migration, which has not started.

Externally: the MCP authorization specification is new (2025), adoption is rising quickly, and there is little **self-hostable, open-source** tooling — the space is dominated by hosted identity vendors. A sovereign, OSS, OAuth-2.1-correct MCP authorization server is an underserved niche, and QAuth is already most of the way into it.

The question this ADR settles: how to sequence near-term work given an accidental, timely, validated capability versus the long-planned federation/PQC vision.

## Decision

Adopt **MCP-first positioning** as QAuth's near-term product identity:

> The open-source, self-hostable OAuth 2.1 authorization server for MCP servers and AI agents.

Wallet federation (ADR-004) and post-quantum signing (ADR-005) are retained as the **long-term platform**, resequenced to follow the MCP work rather than precede it. Concretely:

1. **Productize the existing capability into a turnkey MCP-auth offering.**
   - `@qauth-labs/mcp-guard` — a resource-server-side SDK/middleware that serves `/.well-known/oauth-protected-resource` (RFC 9728), emits the `401 + WWW-Authenticate: Bearer resource_metadata=…` challenge, and validates QAuth-issued tokens (JWKS verification + `aud`/scope checks, or introspection). This is the adoption lever: without it, only the maintainer can wire QAuth to an MCP server.
   - Abuse controls on dynamic client registration: `initial_access_token`-gated mode (open mode becomes opt-in), client TTL/expiry for dynamically-registered clients, optional admin-approval queue.
   - An MCP quickstart and a runnable example (the Claude Code → `memory-mcp` flow), plus `RFC 7009` token revocation.

2. **Build the agent-native authorization substance of Phase 9 as the differentiation.** Agent client type; on-behalf-of delegation via OAuth Token Exchange (RFC 8693, `act` claim); agent scope modes (ReadOnly / Admin / Exec); step-up authentication before dangerous operations; per-agent action audit (extending the existing `audit_logs` table). This is what makes QAuth _more_ than a generic OAuth server for agents.

3. **Defer the ADR-002 identifier-abstraction migration.** It is re-scoped as the **gate for Phase 4 (wallet federation)**, not near-term work. MCP authorization is dominated by client identity, audience binding, and consent — not human multi-credential identity — and runs on the current schema. See the implementation-status note added to ADR-002.

4. **Reprioritize the existing roadmap** (see Consequences) so the open issues map to the new track structure.

The NLnet / NGI grant narrative is treated as **reframable**: an MCP framing ("sovereign authentication for the agentic web") is acceptable and may strengthen a resubmission. The MCP work also directly advances the conformance and hardening milestones already in the grant scope.

## Consequences

### Positive

- Shortest path to an adoptable, differentiated product — the authorization-server core is ~90% complete and live-validated.
- Defers the costly, blocking ADR-002 migration until a second human-identity upstream (wallet/OIDC federation) actually requires it.
- The MCP work directly advances OAuth 2.1 / OIDC conformance and production-hardening goals already on the roadmap.
- Sovereign, self-hostable, OSS MCP authentication is underserved relative to the hosted incumbents.

### Negative

- Drifts from the originally-pitched federation/PQC narrative; requires reframing in any grant update.
- Risk of split focus for a small team — federation and PQC slip further out.
- **Open dynamic client registration is currently live and unguarded** (e.g. on `qauth.naqshi.net`). It must be gated before the project is promoted for adoption. Immediate follow-up.
- New surface area to maintain: an SDK package and agent-delegation semantics.

### Neutral

- No work is discarded — federation (ADR-004) and PQC (ADR-005) remain on the roadmap; only the order changes.
- ADR-002/003/004/005 remain **Accepted** as designs; only their implementation sequence is affected.
- The MCP authorization specification is still evolving; `mcp-guard` must be versioned against a specific spec revision and tracked as the spec changes.

## Related

- [ADR-002: Identifier Abstraction](./002-identifier-abstraction.md) — deferred; re-scoped as the Phase 4 gate
- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md)
- [ADR-004: Wallet-Agnostic VC Federation](./004-wallet-agnostic-federation.md) — long-term platform
- [ADR-005: Post-Quantum Hybrid Signing](./005-pqc-hybrid-signing.md) — long-term platform
- [ADR-006: OAuth Grants and Audience](./006-oauth-grants-and-audience.md) — the foundation this builds on
- PR #156 — `integration/oauth-mcp-stack`; PR #159 — public-client `authorization_code`
- [MCP Authorization specification](https://modelcontextprotocol.io/specification/draft/basic/authorization)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707 — Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707) · [RFC 7591 — Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) · [RFC 8414 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) · [RFC 7009 — Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
