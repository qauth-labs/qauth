# ADR-007: MCP-First Positioning — OAuth 2.1 Authorization Server for MCP / AI Agents

**Status:** Accepted
**Date:** 2026-06-23
**Authors:** QAuth Team

> **Implementation status (2026-06-24):** The near-term MCP track has **shipped**. CIMD client registration is live (config-gated via `CIMD_*`, with SSRF guards and an optional domain trust policy); `@qauth-labs/mcp-guard` ships as the resource-server SDK (PRM discovery, `401`/`403` challenges, JWKS/introspection token validation); the agent-facing `GET /api/clients` developer surface exists; and the T0 trust floor is in place — testcontainers-backed repository tests plus a CI gate running `lint typecheck test build` and a repo-wide coverage threshold. The long-term federation/PQC items below remain accepted designs only (see [ADR-002](./002-identifier-abstraction.md) / [ADR-003](./003-credential-provider-interface.md) / [ADR-004](./004-wallet-agnostic-federation.md) / [ADR-005](./005-pqc-hybrid-signing.md)).
>
> **Activation (2026-07-21, #304): T4 (Federation & PQC) is now the active track, and the "accepted designs only" line above is superseded.** This ADR planned exactly this — federation/PQC "retained as the **long-term platform**, resequenced to follow the MCP work" (§Decision); §Consequences records that "only the order changes." Reaching the "follow" step is fulfillment, not a reversal. Current status: **ADR-002 is IMPLEMENTED** (identifier-abstraction migration complete — Epic #224, PRs #225–#230, migrations 0009–0012); **ADR-003 is implemented** (`CredentialProvider` interface + registry, PR #227); **ADR-004 has shipped code** (`WalletProvider` skeleton, #232 — `verify()` throws by design until the OID4VP flow lands; base-profile flow in progress under Epic #231); **ADR-005 has shipped code** (native + noble ML-DSA-65 backends, #243/#244 — no ML-DSA-signed token emitted yet). The gate this deferral hinged on is therefore **cleared**: the "gated on the ADR-002 schema migration, which has not started" statement (§Context) and "**Defer the ADR-002 identifier-abstraction migration**" (§Decision 3) describe the 2026-06-23 posture and no longer hold. T4 re-activation was the maintainer decision recorded on #296 (2026-07-20).

## Context

The OAuth 2.1 work integrated in PR #156 (`integration/oauth-mcp-stack`) was built, in its own words, for _"first-class MCP / third-party client support."_ It delivered, together and in one release:

- Authorization Server Metadata — `/.well-known/oauth-authorization-server` (RFC 8414)
- OIDC discovery + JWKS — `/.well-known/openid-configuration`, `/.well-known/jwks.json`
- Dynamic Client Registration — `POST /oauth/register` (RFC 7591, open mode)
- Resource Indicators — `resource`-bound, audience-scoped tokens across authorize → code → token → refresh (RFC 8707)
- Public-client (`token_endpoint_auth_method=none`) `authorization_code` + PKCE (PR #159)
- A browser consent screen with session cookies and a revocation surface

This was validated end-to-end: **Claude Code**, configured with only a server URL, drove the full `on-401 → discovery → dynamic registration → authorization_code + PKCE → consent → token` handshake against a live MCP server.

Two facts make this strategically significant:

1. **It was off-roadmap.** "MCP" appears nowhere in the MVP-PRD or README. The capability maps to the PRD's vaguest, furthest-out item — "Phase 9: Agent Authentication & Authorization (TBD)" — whose _protocol foundation_ we have now shipped years ahead of plan. The authorization-server side of the MCP authorization profile is essentially complete and live-tested.

2. **The originally-pitched differentiators are still paper.** Wallet federation ([ADR-004](./004-wallet-agnostic-federation.md)), post-quantum hybrid signing ([ADR-005](./005-pqc-hybrid-signing.md)), and the identifier-abstraction model ([ADR-002](./002-identifier-abstraction.md) / [ADR-003](./003-credential-provider-interface.md)) remain accepted designs with no implementing code. All of Phase 4/5 is gated on the ADR-002 schema migration, which has not started. **[Superseded 2026-07-21, #304: the ADR-002 migration has since completed (Epic #224) and T4 is now active — see the Activation note at the top.]**

Externally: the MCP authorization specification is new (2025), adoption is rising quickly, and there is little **self-hostable, open-source** tooling — the space is dominated by hosted identity vendors. A sovereign, OSS, OAuth-2.1-correct MCP authorization server is an underserved niche, and QAuth is already most of the way into it.

The question this ADR settles: how to sequence near-term work given an accidental, timely, validated capability versus the long-planned federation/PQC vision.

## Decision

Adopt **MCP-first positioning** as QAuth's near-term product identity:

> The open-source, self-hostable OAuth 2.1 authorization server for MCP servers and AI agents.

Wallet federation (ADR-004) and post-quantum signing (ADR-005) are retained as the **long-term platform**, resequenced to follow the MCP work rather than precede it. Concretely:

1. **Productize the existing capability into a turnkey MCP-auth offering.**
   - `@qauth-labs/mcp-guard` — a resource-server-side SDK/middleware that serves `/.well-known/oauth-protected-resource` (RFC 9728), emits the `401 + WWW-Authenticate: Bearer resource_metadata=…` challenge, and validates QAuth-issued tokens (JWKS verification + `aud`/scope checks, or introspection). This is the adoption lever: without it, only the maintainer can wire QAuth to an MCP server.
   - **Client registration: adopt Client ID Metadata Documents (CIMD)** as the primary path per MCP 2025-11-25 — advertise `client_id_metadata_document_supported`, fetch + validate the metadata document (`client_id` == URL, redirect-URI checks, SSRF guards, optional domain trust policy). CIMD keeps no persistent registration records, so it also neutralizes the open-DCR abuse surface. Keep RFC 7591 dynamic registration as the documented fallback, and gate open mode (`initial_access_token`, client TTL, optional approval) for any deployment that still exposes it.
   - **Step-up scope challenges:** `mcp-guard` emits `403 insufficient_scope` + `WWW-Authenticate` scope hints; QAuth supports re-authorization for an increased scope set (MCP 2025-11-25 incremental consent).
   - An MCP quickstart and a runnable example (the Claude Code → `memory-mcp` flow), plus `RFC 7009` token revocation.

2. **Build the agent-native authorization substance of Phase 9 as the differentiation.** Agent client type; on-behalf-of delegation via OAuth Token Exchange (RFC 8693, `act` claim — an additive MCP auth _extension_, not core; see the [ext-auth](https://github.com/modelcontextprotocol/ext-auth) repo); agent scope modes (ReadOnly / Admin / Exec); step-up authentication before dangerous operations; per-agent action audit (extending the existing `audit_logs` table). This is what makes QAuth _more_ than a generic OAuth server for agents.

3. **Defer the ADR-002 identifier-abstraction migration.** It is re-scoped as the **gate for Phase 4 (wallet federation)**, not near-term work. **[Done, not deferred — superseded 2026-07-21, #304: the migration completed via Epic #224 (PRs #225–#230); the Phase 4 gate is cleared and T4 is active. See the Activation note at the top.]** MCP authorization is dominated by client identity, audience binding, and consent — not human multi-credential identity — and runs on the current schema. See the implementation-status note added to ADR-002.

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
- **Open dynamic client registration is unguarded by default.** Any instance exposing the registration endpoint must gate it before the project is promoted for adoption — immediate follow-up; adopting CIMD (see Spec tracking) is the durable fix, since it removes persistent registration records entirely.
- New surface area to maintain: an SDK package and agent-delegation semantics.

### Neutral

- No work is discarded — federation (ADR-004) and PQC (ADR-005) remain on the roadmap; only the order changes.
- ADR-002/003/004/005 remain **Accepted** as designs; only their implementation sequence is affected.
- The MCP authorization specification is still evolving; `mcp-guard` must be versioned against a specific spec revision and tracked as the spec changes.

## Spec tracking

> **Refresh 2026-07-19:** MCP has published a **2026-07-28** revision (release
> candidate; final 2026-07-28). See [Delta: 2025-11-25 to 2026-07-28](#delta-2025-11-25-to-2026-07-28)
> below. The section immediately following remains the 2025-11-25 review, kept
> for the audit trail.

Reviewed against MCP Authorization **revision 2025-11-25** (the revision this ADR targets; the implementation in PR #156 was built to 2025-06-18). Auth-relevant deltas and QAuth's posture:

- **Client ID Metadata Documents (CIMD)** — now the _recommended_ client-registration mechanism (client priority: pre-registered → CIMD → DCR → manual). **RFC 7591 Dynamic Client Registration is explicitly demoted to a backwards-compatibility fallback.** → Reshapes T1: adopt CIMD (Decision §1); it supersedes the earlier "DCR abuse controls" framing because there are no persistent registration records to abuse.
- **Incremental scope consent / step-up authorization** — runtime `403 insufficient_scope` + `WWW-Authenticate` scope challenge; clients re-authorize for a larger scope set. → `mcp-guard` (T1) emits the challenge; richer scope _modes_ stay T2.
- **OIDC Discovery accepted as an AS-metadata alternative**, with OIDC-discovery providers **required** to expose `code_challenge_methods_supported`; the PRM `WWW-Authenticate` header is now optional with a `.well-known` fallback. → **Already satisfied:** QAuth serves both RFC 8414 and OIDC discovery, each carrying `code_challenge_methods_supported: ['S256']`.
- **Delegation / on-behalf-of is not core MCP auth** — it lives in the separate [ext-auth extensions](https://github.com/modelcontextprotocol/ext-auth) repo, so QAuth's RFC 8693 token-exchange work (Decision §2 / T2) is an _extension_, not a core requirement.

Unchanged core QAuth already meets: OAuth 2.1 (public + confidential), PKCE S256 (advertised), RFC 9728 PRM discovery, RFC 8707 resource indicators + audience-bound tokens + audience-validated introspection, public-client refresh-token rotation, and consent.

## Delta: 2025-11-25 to 2026-07-28

Reviewed 2026-07-19 against the [2026-07-28 release candidate](https://blog.modelcontextprotocol.io/posts/2026-07-28-release-candidate/)
and the [draft authorization spec](https://modelcontextprotocol.io/specification/draft/basic/authorization).
Only auth-relevant deltas are listed; the release also adds a stateless protocol
core, an Extensions framework, Tasks, and MCP Apps.

- **RFC 9207 issuer identification — NEW, and QAuth does not implement it.** The
  AS **SHOULD** include `iss` in authorization responses _including error
  responses_, and an AS that does **MUST** advertise
  `authorization_response_iss_parameter_supported: true` in its metadata. The
  spec states a future revision is expected to upgrade this to **MUST**.
  QAuth emits neither. → Tracked as **#282**. This is the one hard gap in the
  delta.
- **Scope guidance on the 401.** Resources **SHOULD** include a `scope` parameter
  in the `WWW-Authenticate` header of the 401, not only on `insufficient_scope`
  (403). `mcp-guard` attaches `scope` to the 403 path only; clients currently
  fall back to PRM `scopes_supported`. → Tracked as **#284**.
- **`offline_access` is a resource anti-pattern.** MCP servers **SHOULD NOT**
  advertise `offline_access` in `WWW-Authenticate` scope or PRM
  `scopes_supported`, since refresh tokens are not a resource requirement. This
  constrains `mcp-guard`; the AS advertising it in `scopes_supported` is
  unaffected and remains correct.
- **CIMD is now SHOULD; DCR is MAY and explicitly deprecated.** In 2025-11-25 CIMD
  was "recommended" and DCR a "backwards-compatibility fallback". The normative
  strength has firmed in the direction ADR-007 already chose. → **No change
  required**; QAuth's client-resolution priority (pre-registered → CIMD → DCR)
  already matches.
- **Both discovery mechanisms remain acceptable** (RFC 8414 _or_ OIDC Discovery),
  with clients required to support both. → **Already satisfied**, unchanged.
- **RFC 8707 resource indicators remain MUST for clients**, with audience
  validation MUST for servers. → **Already satisfied**, unchanged.
- **Extensions moved to a formal framework** with reverse-DNS IDs, capability
  negotiation, independent versioning, and an Extensions Track in the SEP
  process. QAuth's RFC 8693 token-exchange delegation work remains an
  _extension_ (`ext-auth`), not core — the position ADR-007 already took. The
  formalisation makes that boundary firmer, not weaker.

### Underlying spec drift

- **OAuth 2.1 is at `draft-ietf-oauth-v2-1-15`** and is still not an RFC. The MCP
  draft cites `-13` and `-14`. QAuth's "OAuth 2.1" positioning is accurate but
  the base is still moving.
- **CIMD is at `draft-ietf-oauth-client-id-metadata-document-02`** (6 July 2026);
  QAuth and the MCP spec both still cite `-00`. No interop break — but note that
  `-01` added SSRF hardening and required HTTP 200, and `-02` clarified that URL
  comparison is simple string comparison without default-port normalisation.
  **QAuth's implementation already satisfies all of these** (DNS-pinned IP
  validation, no redirect following, https-only, size bounds, non-200 rejection,
  byte-for-byte `client_id` match). The citation lags the code, not the reverse.

### Process note

This refresh, the ADR-004 refresh, and the #274 PQC draft re-pin are the same
failure mode: QAuth's implementation is repeatedly _more_ current than its own
spec citations. The decaying artefacts are the pin constants and ADR
spec-tracking sections, not the code. A standing quarterly re-pin pass would
catch this earlier than an ad-hoc audit does.

## Related

- [ADR-002: Identifier Abstraction](./002-identifier-abstraction.md) — IMPLEMENTED (Epic #224); was the Phase 4 gate, now cleared
- [ADR-003: CredentialProvider Abstraction](./003-credential-provider-interface.md) — implemented (PR #227)
- [ADR-004: Wallet-Agnostic VC Federation](./004-wallet-agnostic-federation.md) — active (T4); `WalletProvider` skeleton shipped (#232), OID4VP flow in progress (Epic #231)
- [ADR-005: Post-Quantum Hybrid Signing](./005-pqc-hybrid-signing.md) — active (T4); ML-DSA-65 backends shipped (#243/#244)
- [ADR-006: OAuth Grants and Audience](./006-oauth-grants-and-audience.md) — the foundation this builds on
- PR #156 — `integration/oauth-mcp-stack`; PR #159 — public-client `authorization_code`
- [MCP Authorization specification (2025-11-25)](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) · [changelog vs 2025-06-18](https://modelcontextprotocol.io/specification/2025-11-25/changelog) · [auth extensions (ext-auth)](https://github.com/modelcontextprotocol/ext-auth)
- [RFC 9728 — OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707 — Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707) · [RFC 7591 — Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591) · [RFC 8414 — Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414) · [OAuth Client ID Metadata Documents (CIMD draft-00)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00)
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) · [RFC 7009 — Token Revocation](https://datatracker.ietf.org/doc/html/rfc7009)
